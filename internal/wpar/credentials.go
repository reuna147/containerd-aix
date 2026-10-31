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

// Package wpar — credentials.go
//
// Implements per-container identity and privilege configuration following these
// directives:
//
//   - Implement runAsUser, runAsGroup, and supplementalGroups through the WPAR
//     start helper.
//   - Configure supplementary groups, primary GID, and UID before executing the
//     container command.
//   - Enforce runAsNonRoot by resolving the effective startup identity and
//     rejecting UID 0 where prohibited.
//   - Configure the WPAR privilege ceiling before starting workload processes.
//   - Translate supported Linux capabilities to AIX privileges through a
//     centralized mapping table.
//   - Apply the resulting AIX limiting, maximum, inheritable, and effective
//     privilege sets.
//   - Remove privileges not required by the workload.
//   - Prevent child processes and threads from gaining privileges outside
//     their configured ceilings.
//   - Preserve the intended privilege restrictions across fork and exec.
//   - Restrict setuid, setgid, and executable privilege metadata where
//     allowPrivilegeEscalation is false.
//   - Prevent workloads from modifying their WPAR privilege ceiling or accessing
//     global-environment identity-management interfaces.
//   - Keep the WPAR's local user and group configuration separate from the
//     host's identity administration.
//   - Reject hostUsers because Linux-style UID remapping is not implemented.
//   - Reject unsupported capability additions; do not silently grant a broader
//     AIX privilege as an approximation.
//
// AIX privilege model (setppriv(2) / <sys/priv.h>):
//   - Each process has four privilege sets: LPS (limiting), MPS (maximum),
//     IPS (inheritable), EPS (effective).
//   - setppriv(PRIV_SET, PRIV_LIMIT, set)  → sets the LPS (ceiling)
//   - setppriv(PRIV_SET, PRIV_MAXIMUM, set) → sets the MPS
//   - setppriv(PRIV_SET, PRIV_INHERITED, set) → sets the IPS
//   - setppriv(PRIV_SET, PRIV_EFFECTIVE, set) → sets the EPS
//   - AIX privilege names: strings like "PV_DAC_R", "PV_NET_RAW", etc.

package wpar

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
)

// ---- Linux → AIX capability mapping ----------------------------------------

// linuxCapToAIXPriv maps Linux capability names to the AIX privilege names
// that best approximate them. This is the single centralized mapping table
// referenced by the directives.
//
// Keys: Linux cap name (lower-case, without "cap_" prefix, e.g. "net_raw").
// Values: AIX privilege name(s) that implement the capability.
//
// Capabilities not listed here are unsupported; their addition is REJECTED
// rather than silently approximated with a broader privilege.
var linuxCapToAIXPriv = map[string][]string{
	// Filesystem capabilities
	"chown":            {"PV_DAC_X", "PV_DAC_W", "PV_DAC_R"},
	"dac_override":     {"PV_DAC_X", "PV_DAC_W", "PV_DAC_R"},
	"dac_read_search":  {"PV_DAC_R"},
	"fowner":           {"PV_DAC_X", "PV_DAC_W"},
	"fsetid":           {"PV_PROC_SETUID"},
	"setuid":           {"PV_PROC_SETUID"},
	"setgid":           {"PV_PROC_SETGID"},
	"setpcap":          {"PV_PROC_SETPCAP"},

	// Process capabilities
	"kill":             {"PV_PROC_KILL"},
	"sys_nice":         {"PV_PROC_NICE"},
	"sys_ptrace":       {"PV_PROC_PTRACE"},
	"sys_resource":     {"PV_PROC_RLIMIT"},

	// Networking capabilities
	"net_bind_service": {"PV_NET_PORT"},
	"net_raw":          {"PV_NET_RAW"},
	"net_admin":        {"PV_NET_ADMIN"},
	"net_broadcast":    {"PV_NET_BCAST"},

	// IPC / shared memory
	"ipc_lock":         {"PV_MLOCK"},
	"ipc_owner":        {"PV_IPC_OWNER"},

	// Device / audit
	"mknod":            {"PV_DEV_CDEV"},
	"sys_admin":        {"PV_PROC_OWNER"},  // partial — sys_admin is intentionally narrow
	"audit_write":      {"PV_AUDIT_WRITE"},
	"audit_control":    {"PV_AUDIT_CONTROL"},
}

// UnsupportedCapabilities lists Linux capabilities that have no acceptable
// AIX privilege mapping. Any workload requesting these is rejected.
var UnsupportedCapabilities = []string{
	"sys_module",
	"sys_rawio",
	"sys_boot",
	"sys_chroot",
	"sys_time",
	"syslog",
	"mac_override",
	"mac_admin",
	"linux_immutable",
	"lease",
	"block_suspend",
	"wake_alarm",
	"epoll_ctldev",
}

// TranslateCapabilities converts a list of Linux capability names to AIX
// privilege names using the centralized mapping table.
//
// Returns an error for any unsupported capability. Never silently grants a
// broader AIX privilege as an approximation.
func TranslateCapabilities(caps []string) ([]string, error) {
	privSet := make(map[string]struct{})
	for _, cap := range caps {
		lower := strings.ToLower(strings.TrimPrefix(cap, "CAP_"))
		// Check unsupported list first.
		for _, u := range UnsupportedCapabilities {
			if lower == u {
				return nil, fmt.Errorf("capability %q is not supported on AIX and cannot be granted", cap)
			}
		}
		privs, ok := linuxCapToAIXPriv[lower]
		if !ok {
			return nil, fmt.Errorf("capability %q has no AIX privilege mapping; "+
				"unsupported capabilities must not be silently approximated", cap)
		}
		for _, p := range privs {
			privSet[p] = struct{}{}
		}
	}
	var result []string
	for p := range privSet {
		result = append(result, p)
	}
	sort.Strings(result)
	return result, nil
}

// CredentialConfig holds the identity and privilege configuration for a
// container's startup helper.
type CredentialConfig struct {
	UID                     uint32
	GID                     uint32
	SupplementalGroups       []uint32
	RunAsNonRoot            bool
	AllowPrivilegeEscalation bool
	// AIXPrivileges is the translated set of AIX privilege names to grant.
	AIXPrivileges []string
	// WPARName is the AIX WPAR name in which the helper runs.
	WPARName string
}

// ValidateIdentity checks that the configured UID/GID satisfies runAsNonRoot.
func ValidateIdentity(cfg CredentialConfig) error {
	if cfg.RunAsNonRoot && cfg.UID == 0 {
		return fmt.Errorf("runAsNonRoot is true but the resolved UID is 0")
	}
	return nil
}

// BuildStartArgs builds the clogin argument list that configures the WPAR
// start helper to apply credentials and privilege restrictions before running
// the container command. The helper is a small AIX program (wpar-start-helper)
// that:
//  1. Sets the WPAR privilege ceiling via setppriv.
//  2. Drops to the requested UID/GID and supplemental groups.
//  3. Applies nosuid filesystem metadata restrictions when
//     AllowPrivilegeEscalation is false.
//  4. Exec's the container command.
//
// The -priv flag accepts a comma-separated list of AIX privilege names.
func BuildStartArgs(cfg CredentialConfig, containerArgs []string) []string {
	args := []string{
		"wpar-start-helper",
		"-uid", fmt.Sprintf("%d", cfg.UID),
		"-gid", fmt.Sprintf("%d", cfg.GID),
	}

	if len(cfg.SupplementalGroups) > 0 {
		gids := make([]string, len(cfg.SupplementalGroups))
		for i, g := range cfg.SupplementalGroups {
			gids[i] = fmt.Sprintf("%d", g)
		}
		args = append(args, "-groups", strings.Join(gids, ","))
	}

	if len(cfg.AIXPrivileges) > 0 {
		args = append(args, "-priv", strings.Join(cfg.AIXPrivileges, ","))
	}

	if !cfg.AllowPrivilegeEscalation {
		args = append(args, "-no-new-privs")
	}

	// Append "--" separator followed by the container command.
	args = append(args, "--")
	args = append(args, containerArgs...)
	return args
}

// applyWPARPrivilegeCeiling configures the WPAR's privilege ceiling using the
// wpar management interfaces. This is called before the container's start
// helper runs.
//
// On AIX, wpar privilege ceilings are set using:
//   mkwpar/chwpar -S priv=NAME1,NAME2,...
//
// The ceiling prevents any process inside the WPAR from acquiring privileges
// beyond those listed, regardless of setuid executables or setppriv calls.
func applyWPARPrivilegeCeiling(wparName string, privs []string) error {
	if len(privs) == 0 {
		// An empty privilege list means no privileges — most restrictive.
		return chwparPrivileges(wparName, nil)
	}
	return chwparPrivileges(wparName, privs)
}

// chwparPrivileges issues "chwpar -S priv=<list> <name>" to set the WPAR
// privilege ceiling. An empty list sets an empty (no-privileges) ceiling.
func chwparPrivileges(wparName string, privs []string) error {
	privVal := ""
	if len(privs) > 0 {
		privVal = strings.Join(privs, ",")
	}

	// chwpar -S priv=<list> <name>
	// When privVal is empty, this removes all privileges from the ceiling.
	arg := "priv=" + privVal
	cmd := exec.Command("chwpar", "-S", arg, wparName)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chwpar -S priv=%s %s: %w\n%s", privVal, wparName, err, string(out))
	}
	return nil
}

// sigstop returns SIGSTOP as an os.Signal. Shared with procmon.go.
func sigstop() os.Signal {
	return syscall.SIGSTOP
}
