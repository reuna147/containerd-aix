//go:build aix

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Package wpar — security_policy.go
//
// Defines the unified per-container/WPAR security policy record that drives
// every preventive control.  Each container has exactly one SecurityPolicy;
// it is constructed from the OCI spec / Kubernetes securityContext at creation
// time and must be fully applied before the container's initial process is
// released from its startup stop.
//
// The record covers:
//   - Syscall restrictions     (→ kmod_util)
//   - Privileges               (→ credentials.go / setppriv)
//   - Identity                 (→ credentials.go / WPAR start helper)
//   - Filesystem configuration (→ fs_isolation.go)
//   - Device access            (none on AIX beyond privilege restrictions)
//   - Resource controls        (→ wlm.go)
//   - Network restrictions     (→ network.go)
//   - D&R rules                (→ procmon.go)
//
// The record is persisted to disk (alongside wpar-state.json) so it can be
// reconciled after a runtime restart.

package wpar

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SecurityPolicy is the single source of truth for all security controls
// applied to a managed container/WPAR.
type SecurityPolicy struct {
	mu sync.RWMutex

	// ContainerID is the containerd task ID.
	ContainerID string `json:"container_id"`

	// WparID is the numeric AIX WPAR identifier (from lswpar).
	WparID uint32 `json:"wpar_id"`

	// --- Syscall restrictions ------------------------------------------------
	// SyscallBitmap is the allow/deny bitmap registered with kmod_util.
	SyscallBitmap SyscallBitmap `json:"syscall_bitmap"`

	// --- Identity and privilege ----------------------------------------------
	UID                      uint32   `json:"uid"`
	GID                      uint32   `json:"gid"`
	SupplementalGroups       []uint32 `json:"supplemental_groups,omitempty"`
	RunAsNonRoot             bool     `json:"run_as_non_root"`
	AllowPrivilegeEscalation bool     `json:"allow_privilege_escalation"`
	// RequestedCapabilities lists the Linux capability names requested by the
	// workload (before translation to AIX privileges).
	RequestedCapabilities []string `json:"requested_capabilities,omitempty"`
	// AIXPrivileges lists the resolved AIX privilege names to grant.
	AIXPrivileges []string `json:"aix_privileges,omitempty"`

	// --- Filesystem configuration -------------------------------------------
	ReadOnlyRootFS        bool        `json:"read_only_root_fs"`
	Mounts                []MountSpec `json:"mounts,omitempty"`
	AllowedHostPaths      []string    `json:"allowed_host_paths,omitempty"`
	MountPropagationCheck bool        `json:"mount_propagation_check"`

	// --- Resource controls ---------------------------------------------------
	Resources ResourcePolicy `json:"resources"`

	// --- Network restrictions ------------------------------------------------
	Network NetworkPolicy `json:"network"`

	// --- D&R rules -----------------------------------------------------------
	DRRules []DRRule `json:"dr_rules,omitempty"`

	// --- Rejection flags -----------------------------------------------------
	// These are set when the workload requested a feature that must be rejected.
	RejectHostPID               bool `json:"reject_host_pid,omitempty"`
	RejectHostIPC               bool `json:"reject_host_ipc,omitempty"`
	RejectHostUsers             bool `json:"reject_host_users,omitempty"`
	RejectShareProcessNamespace bool `json:"reject_share_process_namespace,omitempty"`
}

// MountSpec describes a single filesystem mount for the container.
type MountSpec struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Type        string `json:"type"` // e.g. "namefs", "tmpfs", "bind"
	ReadOnly    bool   `json:"read_only"`
	NoSUID      bool   `json:"no_suid"`
	NoDev       bool   `json:"no_dev"`
	NoExec      bool   `json:"no_exec"`
	Propagation string `json:"propagation,omitempty"` // "" or "private" only; others → reject
}

// ResourcePolicy holds WLM-level resource constraints.
type ResourcePolicy struct {
	// CPU
	CPUShares   uint64  `json:"cpu_shares,omitempty"`
	CPULimitPct float64 `json:"cpu_limit_pct,omitempty"` // 0–100, translated from K8s limits

	// Memory
	MemoryLimitBytes   int64 `json:"memory_limit_bytes,omitempty"`
	MemoryRequestBytes int64 `json:"memory_request_bytes,omitempty"`

	// Process / thread
	MaxProcesses int `json:"max_processes,omitempty"`
	MaxThreads   int `json:"max_threads,omitempty"`

	// Ephemeral storage
	EphemeralStorageLimitBytes int64 `json:"ephemeral_storage_limit_bytes,omitempty"`

	// QoS class as reported to kubelet ("Guaranteed", "Burstable", "BestEffort").
	QoSClass string `json:"qos_class,omitempty"`
}

// NetworkPolicy holds network-restriction settings.
type NetworkPolicy struct {
	// ExposedPorts lists ports the container is allowed to bind.
	ExposedPorts []ExposedPort `json:"exposed_ports,omitempty"`
	// AllowRawSockets permits CAP_NET_RAW equivalent on AIX.
	AllowRawSockets bool `json:"allow_raw_sockets,omitempty"`
	// AllowPrivilegedPorts permits binding ports < 1024.
	AllowPrivilegedPorts bool `json:"allow_privileged_ports,omitempty"`
	// HostNetworking indicates whether the workload accepts host networking
	// (true) or requests pod-network isolation (false). All WPARs share the
	// host network; only hostNetwork=true is supported. Setting this false
	// (i.e., requesting pod isolation) is rejected until a network plugin
	// is available.
	HostNetworking bool `json:"host_networking,omitempty"`
}

// ExposedPort is a single port reservation.
type ExposedPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

// securityPolicyPath returns the path to the persisted SecurityPolicy JSON.
func securityPolicyPath(bundlePath string) string {
	return filepath.Join(bundlePath, "security-policy.json")
}

// Save persists the SecurityPolicy to disk with mode 0600.
func (p *SecurityPolicy) Save(bundlePath string) error {
	p.mu.RLock()
	data, err := json.Marshal(p)
	p.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal security policy: %w", err)
	}
	return os.WriteFile(securityPolicyPath(bundlePath), data, 0600)
}

// LoadSecurityPolicy reads and deserialises the SecurityPolicy from bundlePath.
func LoadSecurityPolicy(bundlePath string) (*SecurityPolicy, error) {
	data, err := os.ReadFile(securityPolicyPath(bundlePath))
	if err != nil {
		return nil, fmt.Errorf("read security policy: %w", err)
	}
	var p SecurityPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal security policy: %w", err)
	}
	return &p, nil
}

// Validate returns an error if the policy contains any unsupported or rejected
// configuration. This check runs before the WPAR is created.
func (p *SecurityPolicy) Validate() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.RejectHostPID {
		return fmt.Errorf("hostPID requires sharing across WPAR boundaries: not supported")
	}
	if p.RejectHostIPC {
		return fmt.Errorf("hostIPC requires sharing across WPAR boundaries: not supported")
	}
	if p.RejectHostUsers {
		return fmt.Errorf("hostUsers (Linux UID remapping) is not implemented on AIX")
	}
	if p.RejectShareProcessNamespace {
		return fmt.Errorf("shareProcessNamespace requires sharing across WPAR boundaries: not supported")
	}
	// WPARs always use host networking. Reject requests for pod-network isolation
	// (hostNetwork: false) until a network plugin provides per-pod addresses.
	if !p.Network.HostNetworking {
		return fmt.Errorf("pod network isolation (hostNetwork=false) is not supported; " +
			"all WPARs share the host network — set hostNetwork=true")
	}
	for _, m := range p.Mounts {
		switch m.Propagation {
		case "", "private":
			// supported
		default:
			return fmt.Errorf("unsupported mount propagation mode %q on AIX", m.Propagation)
		}
	}
	if p.RunAsNonRoot && p.UID == 0 {
		return fmt.Errorf("runAsNonRoot is true but resolved UID is 0")
	}
	return nil
}

// Clone returns a deep copy of the policy with a fresh mutex.
func (p *SecurityPolicy) Clone() SecurityPolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Copy only the non-mutex fields to avoid "assignment copies lock value".
	cp := SecurityPolicy{
		ContainerID:              p.ContainerID,
		WparID:                   p.WparID,
		SyscallBitmap:            p.SyscallBitmap,
		UID:                      p.UID,
		GID:                      p.GID,
		RunAsNonRoot:             p.RunAsNonRoot,
		AllowPrivilegeEscalation: p.AllowPrivilegeEscalation,
		ReadOnlyRootFS:           p.ReadOnlyRootFS,
		MountPropagationCheck:    p.MountPropagationCheck,
		Resources:                p.Resources,
		Network: NetworkPolicy{
			AllowRawSockets:      p.Network.AllowRawSockets,
			AllowPrivilegedPorts: p.Network.AllowPrivilegedPorts,
			HostNetworking:       p.Network.HostNetworking,
		},
		RejectHostPID:               p.RejectHostPID,
		RejectHostIPC:               p.RejectHostIPC,
		RejectHostUsers:             p.RejectHostUsers,
		RejectShareProcessNamespace: p.RejectShareProcessNamespace,
	}
	cp.SupplementalGroups = append([]uint32(nil), p.SupplementalGroups...)
	cp.RequestedCapabilities = append([]string(nil), p.RequestedCapabilities...)
	cp.AIXPrivileges = append([]string(nil), p.AIXPrivileges...)
	cp.Mounts = append([]MountSpec(nil), p.Mounts...)
	cp.AllowedHostPaths = append([]string(nil), p.AllowedHostPaths...)
	cp.DRRules = append([]DRRule(nil), p.DRRules...)
	cp.Network.ExposedPorts = append([]ExposedPort(nil), p.Network.ExposedPorts...)
	return cp
}

// policyRegistryPath returns the path for the runtime-wide registry that maps
// container IDs to their bundle paths. This allows the runtime to enumerate
// all managed WPARs on restart.
func policyRegistryPath(stateDir string) string {
	return filepath.Join(stateDir, "wpar-policy-registry.json")
}

// PolicyRegistry maps container IDs to bundle paths for runtime recovery.
type PolicyRegistry struct {
	mu      sync.Mutex
	Entries map[string]string `json:"entries"` // containerID → bundlePath
	path    string
}

// NewPolicyRegistry opens or creates the registry at the given state directory.
func NewPolicyRegistry(stateDir string) (*PolicyRegistry, error) {
	r := &PolicyRegistry{
		Entries: make(map[string]string),
		path:    policyRegistryPath(stateDir),
	}
	data, err := os.ReadFile(r.path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read policy registry: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &r.Entries); err != nil {
			return nil, fmt.Errorf("parse policy registry: %w", err)
		}
	}
	return r, nil
}

// Add registers a container→bundle mapping and persists the registry.
func (r *PolicyRegistry) Add(containerID, bundlePath string) error {
	r.mu.Lock()
	r.Entries[containerID] = bundlePath
	data, err := json.Marshal(r.Entries)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0600)
}

// Remove deletes a container entry and persists the registry.
func (r *PolicyRegistry) Remove(containerID string) error {
	r.mu.Lock()
	delete(r.Entries, containerID)
	data, err := json.Marshal(r.Entries)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0600)
}

// All returns a snapshot of all registered container→bundle mappings.
func (r *PolicyRegistry) All() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.Entries))
	for k, v := range r.Entries {
		out[k] = v
	}
	return out
}
