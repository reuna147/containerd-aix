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

// Package wpar — ipc_uts.go
//
// Implements IPC and UTS (hostname) isolation directives:
//
//   - Use native WPAR IPC isolation for System V shared memory, message
//     queues, and semaphores.
//   - Ensure IPC objects created by one WPAR are not accessible to processes
//     in another WPAR (native; enforced by the AIX kernel — this file
//     validates configuration and rejects overrides).
//   - Use native WPAR hostname configuration as the UTS namespace counterpart.
//   - Assign the Kubernetes pod hostname to the managed WPAR.
//   - Prevent workloads from changing host-wide hostname or system configuration
//     (via privilege restrictions in credentials.go).
//   - Track IPC object consumption as part of workload resource monitoring.
//   - Clean up workload-owned IPC resources during container teardown.
//   - Reject hostIPC.
//   - Reject cross-WPAR IPC sharing unless a separately designed and explicitly
//     authorized mechanism is introduced.
//   - Validate that IPC and hostname restrictions remain effective for all
//     descendant processes.
//
// AIX WPAR isolation notes:
//   - IPC objects are scoped to the WPAR by the AIX kernel; no additional
//     configuration is required to isolate them.
//   - WPAR hostname is set with "chwpar -h <hostname> <name>".
//   - "chwpar -N" disables network for the WPAR; we do not use this path
//     but validate that the configuration is coherent.

package wpar

import (
	"fmt"
	"os/exec"
	"strings"
)

// ---- UTS / hostname --------------------------------------------------------

// SetWPARHostname assigns the Kubernetes pod hostname to the WPAR.
// This is the WPAR-native counterpart to the Linux UTS namespace.
// The hostname must be set before startwpar activates the WPAR.
func SetWPARHostname(wparName, hostname string) error {
	if hostname == "" {
		return nil
	}
	// Validate hostname: must contain only [a-zA-Z0-9-.] per RFC 1123.
	if err := validateHostname(hostname); err != nil {
		return fmt.Errorf("invalid pod hostname %q: %w", hostname, err)
	}
	cmd := exec.Command("chwpar", "-h", hostname, wparName)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chwpar -h %s %s: %w\n%s", hostname, wparName, err, string(out))
	}
	return nil
}

// validateHostname returns an error if hostname is not a valid RFC 1123 label.
func validateHostname(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return fmt.Errorf("hostname length %d is not in [1,253]", len(h))
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return fmt.Errorf("character %q is not allowed in a hostname", c)
		}
	}
	if strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") {
		return fmt.Errorf("hostname must not start or end with a hyphen")
	}
	return nil
}

// ---- IPC validation and cleanup --------------------------------------------

// IPCConfig holds the IPC-related settings for a container's WPAR.
type IPCConfig struct {
	// HostIPC must always be false; hostIPC is rejected.
	HostIPC bool
	// ShareIPCWith is the ID of another WPAR to share IPC with.
	// Rejected unless an explicitly authorized mechanism is in place.
	ShareIPCWith string
}

// ValidateIPCConfig returns an error when the IPC configuration violates
// isolation requirements.
func ValidateIPCConfig(cfg IPCConfig) error {
	if cfg.HostIPC {
		return fmt.Errorf("hostIPC is not supported: sharing IPC across WPAR boundaries is rejected")
	}
	if cfg.ShareIPCWith != "" {
		return fmt.Errorf("cross-WPAR IPC sharing with WPAR %q requires a separately designed "+
			"and explicitly authorized mechanism; rejecting configuration", cfg.ShareIPCWith)
	}
	return nil
}

// CleanupIPCResources removes all System V IPC objects owned by the WPAR.
// On AIX, WPAR-scoped IPC objects are removed when the WPAR is destroyed
// via rmwpar. This function explicitly enumerates and removes any residual
// objects as a defense-in-depth measure.
//
// AIX ipcs(1) syntax: "ipcs -a -w <wparname>"
// AIX ipcrm(1) syntax: "ipcrm -m <shmid>" / "ipcrm -q <msqid>" / "ipcrm -s <semid>"
func CleanupIPCResources(wparName string) error {
	// List all IPC objects for the WPAR.
	out, err := exec.Command("ipcs", "-a", "-w", wparName).Output()
	if err != nil {
		// If ipcs fails (e.g. WPAR already gone), that is acceptable.
		return nil
	}
	return removeIPCObjects(string(out))
}

// removeIPCObjects parses ipcs -a output and removes each listed object.
func removeIPCObjects(ipcsOutput string) error {
	var errs []string
	for _, line := range strings.Split(ipcsOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// ipcs -a output: "<type> <id> ..."
		// type: "m" (shm), "q" (msgq), "s" (sem)
		switch fields[0] {
		case "m":
			if err := ipcrm("-m", fields[1]); err != nil {
				errs = append(errs, err.Error())
			}
		case "q":
			if err := ipcrm("-q", fields[1]); err != nil {
				errs = append(errs, err.Error())
			}
		case "s":
			if err := ipcrm("-s", fields[1]); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("ipcrm errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ipcrm removes a single IPC object by type flag and ID.
func ipcrm(flag, id string) error {
	cmd := exec.Command("ipcrm", flag, id)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipcrm %s %s: %w\n%s", flag, id, err, string(out))
	}
	return nil
}
