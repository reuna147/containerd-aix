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

// Package wpar — network.go
//
// Implements network restriction directives:
//
//   - Restrict network-administration privileges inside each WPAR (via
//     privilege restrictions in credentials.go — PV_NET_ADMIN removal).
//   - Restrict raw-socket creation through the AIX privilege model
//     (PV_NET_RAW withheld unless AllowRawSockets).
//   - Control privileged-port binding through the corresponding AIX privilege
//     restrictions (PV_NET_PORT withheld unless AllowPrivilegedPorts).
//   - Prevent workloads from modifying global routing tables, network
//     interfaces, and host-level network configuration (PV_NET_ADMIN absent
//     from WPAR privilege ceiling — enforced in credentials.go).
//   - Maintain a per-container registry of exposed and reserved ports.
//   - Detect and reject conflicting port allocations before container startup.
//   - Integrate network activity monitoring with the runtime's existing audit
//     and D&R facilities (done through procmon.go D&R rules).
//   - Keep network-security policy decisions separate from the syscall-filter
//     bitmap.
//   - Do not claim per-pod network isolation while host networking is used.
//   - Reject configurations requiring dedicated pod IP addresses or Kubernetes
//     NetworkPolicy enforcement.
//   - Design the network interface so that per-WPAR addressing and IPAM can be
//     added later without replacing the WPAR runtime.

package wpar

import (
	"fmt"
	"sync"
)

// PortRegistry is the runtime-wide registry of reserved ports.  It detects
// and rejects conflicting port allocations before container startup.
// Safe for concurrent use.
type PortRegistry struct {
	mu       sync.Mutex
	reserved map[portKey]string // portKey → containerID that reserved it
}

type portKey struct {
	port     int
	protocol string
}

// globalPortRegistry is the package-level singleton.
var globalPortRegistry = &PortRegistry{
	reserved: make(map[portKey]string),
}

// Reserve claims all ports listed in ports for containerID. Returns an error
// if any port is already reserved by a different container. Reservations are
// all-or-nothing: on conflict, no ports are reserved.
func (r *PortRegistry) Reserve(containerID string, ports []ExposedPort) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Pre-check for conflicts.
	for _, p := range ports {
		k := portKey{port: p.Port, protocol: p.Protocol}
		if existing, ok := r.reserved[k]; ok && existing != containerID {
			return fmt.Errorf("port %d/%s is already reserved by container %s",
				p.Port, p.Protocol, existing)
		}
	}
	// Claim all ports.
	for _, p := range ports {
		r.reserved[portKey{port: p.Port, protocol: p.Protocol}] = containerID
	}
	return nil
}

// Release removes all port reservations for containerID.
func (r *PortRegistry) Release(containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, owner := range r.reserved {
		if owner == containerID {
			delete(r.reserved, k)
		}
	}
}

// ---- Network policy validation --------------------------------------------

// ValidateNetworkPolicy checks the network configuration for unsupported or
// rejected settings.
//
// WPARs always share the host network; hostNetwork=false (pod isolation) is
// rejected until a CNI plugin is available.
func ValidateNetworkPolicy(policy NetworkPolicy, containerID string) error {
	if !policy.HostNetworking {
		return fmt.Errorf("container %s: pod network isolation (hostNetwork=false) "+
			"is not supported; all WPARs share the host network", containerID)
	}
	// We do not support dedicated pod IP addresses or Kubernetes NetworkPolicy
	// enforcement in this release.
	return nil
}

// ApplyNetworkReservations pre-registers the container's port reservations.
// Must be called before container startup to detect conflicts early.
func ApplyNetworkReservations(containerID string, policy NetworkPolicy) error {
	if err := ValidateNetworkPolicy(policy, containerID); err != nil {
		return err
	}
	return globalPortRegistry.Reserve(containerID, policy.ExposedPorts)
}

// ReleaseNetworkReservations releases all port reservations for containerID.
// Called during container teardown.
func ReleaseNetworkReservations(containerID string) {
	globalPortRegistry.Release(containerID)
}

// NetworkPrivilegesForPolicy returns the AIX privilege names that must be
// added or withheld based on the NetworkPolicy. This list is merged into the
// credential configuration in credentials.go.
//
// Network-security policy decisions are kept separate from the syscall bitmap.
func NetworkPrivilegesForPolicy(policy NetworkPolicy) (add []string, remove []string) {
	if policy.AllowRawSockets {
		add = append(add, "PV_NET_RAW")
	} else {
		remove = append(remove, "PV_NET_RAW")
	}

	if policy.AllowPrivilegedPorts {
		add = append(add, "PV_NET_PORT")
	} else {
		remove = append(remove, "PV_NET_PORT")
	}

	// Network administration privileges are always removed from workloads.
	remove = append(remove,
		"PV_NET_ADMIN",
		"PV_NET_CONFIG",
	)

	return add, remove
}
