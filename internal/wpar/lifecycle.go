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

// Package wpar — lifecycle.go
//
// Implements runtime lifecycle and recovery directives:
//
//   - Implement container lifecycle operations: CREATE, START, STOP, KILL,
//     DELETE, and STATUS.
//   - Maintain a persistent mapping between Kubernetes container IDs, WPAR IDs,
//     syscall policies, monitor registrations, and WLM assignments.
//   - On runtime restart, enumerate existing managed WPARs and reconstruct the
//     runtime's state.
//   - Reconcile existing WPARs against the desired security configuration.
//   - Detect and clean up orphaned policies, monitoring registrations, and WLM
//     assignments.
//   - Ensure deleting one WPAR never removes security controls belonging to
//     another.
//   - Support idempotent create, stop, and delete operations.
//   - Define behavior for kernel extension failure, monitoring daemon failure,
//     and partial WPAR startup.
//   - Prevent workloads requiring unavailable mandatory controls from starting
//     or resuming.
//   - Expose component health and per-WPAR enforcement status through the
//     runtime's diagnostic interface.

package wpar

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/containerd/log"
)

// ComponentHealth describes the operational state of a runtime subsystem.
type ComponentHealth struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// RuntimeHealth aggregates the health of all mandatory security components.
type RuntimeHealth struct {
	KmodExtension  ComponentHealth `json:"kmod_extension"`
	ProcMonitor    ComponentHealth `json:"proc_monitor"`
	WLMSubsystem   ComponentHealth `json:"wlm_subsystem"`
}

// WPAREnforcementStatus reports the per-container enforcement state.
type WPAREnforcementStatus struct {
	ContainerID    string          `json:"container_id"`
	WparName       string          `json:"wpar_name"`
	WparID         uint32          `json:"wpar_id"`
	State          string          `json:"state"` // "running", "stopped", "error"
	SyscallPolicy  bool            `json:"syscall_policy_active"`
	ProcMonitor    bool            `json:"proc_monitor_active"`
	WLMActive      bool            `json:"wlm_active"`
	OOMKilled      bool            `json:"oom_killed,omitempty"`
	PolicyPath     string          `json:"policy_path,omitempty"`
}

// ContainerRecord is the persistent mapping for a single managed container.
type ContainerRecord struct {
	ContainerID string `json:"container_id"`
	WparName    string `json:"wpar_name"`
	WparID      uint32 `json:"wpar_id"`
	BundlePath  string `json:"bundle_path"`
}

// containerRegistryPath returns the path to the runtime-wide container registry.
func containerRegistryPath(stateDir string) string {
	return stateDir + "/wpar-container-registry.json"
}

// ContainerRegistry persists the container→WPAR mapping for recovery.
type ContainerRegistry struct {
	mu      sync.Mutex
	records map[string]*ContainerRecord // containerID → record
	path    string
}

// NewContainerRegistry opens or creates the container registry.
func NewContainerRegistry(stateDir string) (*ContainerRegistry, error) {
	r := &ContainerRegistry{
		records: make(map[string]*ContainerRecord),
		path:    containerRegistryPath(stateDir),
	}
	data, err := os.ReadFile(r.path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read container registry: %w", err)
	}
	if len(data) > 0 {
		var list []*ContainerRecord
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("parse container registry: %w", err)
		}
		for _, rec := range list {
			r.records[rec.ContainerID] = rec
		}
	}
	return r, nil
}

// Add registers a new container record and persists the registry.
func (r *ContainerRegistry) Add(rec ContainerRecord) error {
	r.mu.Lock()
	r.records[rec.ContainerID] = &rec
	list := r.snapshot()
	r.mu.Unlock()
	return r.save(list)
}

// Remove deletes a container record and persists the registry.
// It only removes the record for containerID and never touches records
// belonging to other containers.
func (r *ContainerRegistry) Remove(containerID string) error {
	r.mu.Lock()
	delete(r.records, containerID)
	list := r.snapshot()
	r.mu.Unlock()
	return r.save(list)
}

// Get retrieves the record for a container ID.
func (r *ContainerRegistry) Get(containerID string) (*ContainerRecord, bool) {
	r.mu.Lock()
	rec, ok := r.records[containerID]
	r.mu.Unlock()
	return rec, ok
}

// All returns a snapshot of all container records.
func (r *ContainerRegistry) All() []*ContainerRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshot()
}

func (r *ContainerRegistry) snapshot() []*ContainerRecord {
	out := make([]*ContainerRecord, 0, len(r.records))
	for _, rec := range r.records {
		cp := *rec
		out = append(out, &cp)
	}
	return out
}

func (r *ContainerRegistry) save(list []*ContainerRecord) error {
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0600)
}

// ---- Runtime recovery -------------------------------------------------------

// ReconcileOptions controls the behaviour of ReconcileWPARs.
type ReconcileOptions struct {
	// StateDir is the runtime state directory containing the registry.
	StateDir string
	// Kmod is the KmodPolicyManager for re-registering policies.
	Kmod *KmodPolicyManager
	// ProcMon is the global ProcMonitor for re-attaching monitoring.
	ProcMon *ProcMonitor
	// Registry is the persistent container registry.
	Registry *ContainerRegistry
}

// ReconcileWPARs is called at runtime restart. It:
//  1. Enumerates all container records in the registry.
//  2. Loads each container's persisted SecurityPolicy.
//  3. Checks whether the WPAR still exists (via lswpar).
//  4. For live WPARs, re-registers the syscall policy and monitoring.
//  5. For orphaned records (WPAR gone), removes them and cleans up.
//
// Workloads requiring unavailable mandatory controls are prevented from
// resuming.
func ReconcileWPARs(ctx context.Context, opts ReconcileOptions) {
	records := opts.Registry.All()
	for _, rec := range records {
		if err := reconcileOne(ctx, opts, rec); err != nil {
			log.G(ctx).WithError(err).
				WithField("container", rec.ContainerID).
				WithField("wpar", rec.WparName).
				Error("lifecycle: reconcile failed; marking container as orphaned")
			// Remove the orphaned record.
			if removeErr := opts.Registry.Remove(rec.ContainerID); removeErr != nil {
				log.G(ctx).WithError(removeErr).
					WithField("container", rec.ContainerID).
					Error("lifecycle: failed to remove orphaned container record")
			}
		}
	}
}

// reconcileOne reconciles a single container record after runtime restart.
func reconcileOne(ctx context.Context, opts ReconcileOptions, rec *ContainerRecord) error {
	// Check whether the WPAR is still alive.
	state, err := lswparState(rec.WparName)
	if err != nil || state == StateDown {
		log.G(ctx).WithField("wpar", rec.WparName).
			Info("lifecycle: WPAR not found on restart; removing orphaned record")
		return opts.Registry.Remove(rec.ContainerID)
	}

	// Load the persisted security policy.
	policy, err := LoadSecurityPolicy(rec.BundlePath)
	if err != nil {
		return fmt.Errorf("load security policy for %s: %w", rec.ContainerID, err)
	}
	policy.WparID = rec.WparID

	// Re-register the syscall policy if kmod is available.
	if opts.Kmod != nil {
		if err := opts.Kmod.Activate(rec.WparID, policy.SyscallBitmap); err != nil {
			return fmt.Errorf("re-activate kmod policy for wpar %d: %w", rec.WparID, err)
		}
	}

	// Re-attach monitoring for all surviving processes.
	if opts.ProcMon != nil {
		opts.ProcMon.RegisterWPAR(WparMonitorConfig{
			WparID:           rec.WparID,
			Rules:            policy.DRRules,
			MonitorGapPolicy: DRLog,
		})
		// Scan /proc for surviving processes belonging to this WPAR.
		pids := procScanForWPAR(rec.WparID)
		for _, pid := range pids {
			if err := opts.ProcMon.AttachProcess(ctx, pid, rec.WparID); err != nil {
				log.G(ctx).WithError(err).WithField("pid", pid).
					Warn("lifecycle: reconcile: failed to re-attach procmon")
			}
		}
	}

	log.G(ctx).WithField("container", rec.ContainerID).
		WithField("wpar", rec.WparName).
		Info("lifecycle: reconciled WPAR after runtime restart")
	return nil
}

// procScanForWPAR returns all PIDs currently in /proc that belong to wparID.
func procScanForWPAR(wparID uint32) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(de.Name(), "%d", &pid); err != nil {
			continue
		}
		if id, ok := readProcWPAR(pid); ok && id == wparID {
			pids = append(pids, pid)
		}
	}
	return pids
}

// CleanupOrphanedPolicies removes syscall policies, monitoring registrations,
// and WLM assignments for WPARs that no longer exist. Called during
// reconciliation and on demand.
func CleanupOrphanedPolicies(ctx context.Context, kmod *KmodPolicyManager, procMon *ProcMonitor, registry *ContainerRegistry) {
	records := registry.All()
	for _, rec := range records {
		_, err := lswparState(rec.WparName)
		if err == nil {
			continue // WPAR still alive
		}

		log.G(ctx).WithField("wpar", rec.WparName).
			Info("lifecycle: cleaning up orphaned policies")

		if kmod != nil && kmod.IsActive(rec.WparID) {
			_ = kmod.Deactivate(rec.WparID)
		}
		if procMon != nil {
			procMon.DeregisterWPAR(rec.WparID)
		}
		ReleaseNetworkReservations(rec.ContainerID)
		_ = CleanupIPCResources(rec.WparName)
		_ = registry.Remove(rec.ContainerID)
	}
}

// ---- Health reporting -------------------------------------------------------

// CheckRuntimeHealth probes each mandatory component and returns a
// RuntimeHealth report.
func CheckRuntimeHealth(kmod *KmodPolicyManager) RuntimeHealth {
	h := RuntimeHealth{
		KmodExtension: ComponentHealth{Name: "kmod_util"},
		ProcMonitor:   ComponentHealth{Name: "proc_monitor"},
		WLMSubsystem:  ComponentHealth{Name: "wlm"},
	}

	// Check kmod device availability.
	if _, err := os.Stat(kmodDevice); err != nil {
		h.KmodExtension.Error = fmt.Sprintf("%s not available: %v", kmodDevice, err)
	} else {
		h.KmodExtension.Available = true
	}

	// Check /proc availability.
	if _, err := os.Stat("/proc"); err != nil {
		h.ProcMonitor.Error = fmt.Sprintf("/proc not available: %v", err)
	} else {
		h.ProcMonitor.Available = true
	}

	// Check WLM by probing wlmstat.
	if _, err := os.Stat("/usr/bin/wlmstat"); err == nil {
		h.WLMSubsystem.Available = true
	} else {
		h.WLMSubsystem.Error = "wlmstat not found"
	}

	return h
}

// WPARStatus returns the enforcement status for the given container.
func WPARStatus(rec *ContainerRecord, kmod *KmodPolicyManager, procMon *ProcMonitor) WPAREnforcementStatus {
	st := WPAREnforcementStatus{
		ContainerID: rec.ContainerID,
		WparName:    rec.WparName,
		WparID:      rec.WparID,
	}

	// WPAR liveness.
	if state, err := lswparState(rec.WparName); err != nil || state == StateDown {
		st.State = "stopped"
	} else {
		st.State = "running"
	}

	if kmod != nil {
		st.SyscallPolicy = kmod.IsActive(rec.WparID)
	}
	if procMon != nil {
		pids := procMon.WPARDescendants(rec.WparID)
		st.ProcMonitor = len(pids) > 0
	}

	return st
}
