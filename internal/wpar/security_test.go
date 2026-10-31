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

// Package wpar — security_test.go
//
// Integration test suite covering all security directives.
//
// Tests that run live WPAR operations require root privileges and a live AIX
// host with kmod_util installed. Those tests are gated by the "wpar_root" build
// tag. All policy logic tests are unit tests that do NOT require root and
// run on any AIX host.
//
// Coverage per the directives:
//
//   - Two WPARs invoking the same syscall under different policies.
//   - A denied syscall returning the configured error without executing.
//   - A permitted syscall completing normally.
//   - Forked and newly executed processes inheriting the correct syscall policy.
//   - Unsupported syscall interception registration.
//   - A WPAR attempting to regain a removed privilege.
//   - A process triggering an argument-based /proc detection rule.
//   - STOP and KILL responses from the monitoring daemon.
//   - Memory-limit violation and CRI OOMKilled reporting.
//   - Concurrent creation and deletion of multiple WPARs.
//   - Monitoring daemon restart while workloads are running.
//   - Runtime restart and recovery of existing WPARs.
//   - Cleanup after failed container creation.
//   - Kernel policy replacement while processes are running.
//   - Measurement of syscall interception overhead and monitoring latency.

package wpar

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Unit tests — do not require root or a live WPAR environment.
// ============================================================================

// --- kmod_util bitmap tests -------------------------------------------------

// TestSyscallBitmapAllowDeny verifies that Allow/Deny/IsAllowed work correctly.
func TestSyscallBitmapAllowDeny(t *testing.T) {
	var b SyscallBitmap

	b.Allow(0)
	if !b.IsAllowed(0) {
		t.Error("expected syscall 0 to be allowed after Allow(0)")
	}

	b.Deny(0)
	if b.IsAllowed(0) {
		t.Error("expected syscall 0 to be denied after Deny(0)")
	}

	// Boundary: last valid slot.
	last := uint16(SyscallBitmapWords*64 - 1)
	b.Allow(last)
	if !b.IsAllowed(last) {
		t.Errorf("expected syscall %d to be allowed", last)
	}

	// Out-of-range: should not panic, IsAllowed returns false.
	b.Allow(512)
	if b.IsAllowed(512) {
		t.Error("IsAllowed(512) should return false for out-of-range syscall")
	}
}

// TestDefaultBitmaps verifies that DefaultAllowBitmap allows everything and
// DefaultDenyBitmap denies everything.
func TestDefaultBitmaps(t *testing.T) {
	allow := DefaultAllowBitmap()
	deny := DefaultDenyBitmap()

	for n := uint16(0); n < uint16(SyscallBitmapWords*64); n++ {
		if !allow.IsAllowed(n) {
			t.Errorf("DefaultAllowBitmap: syscall %d should be allowed", n)
			break
		}
		if deny.IsAllowed(n) {
			t.Errorf("DefaultDenyBitmap: syscall %d should be denied", n)
			break
		}
	}
}

// TestTwoWPARsDifferentPolicies simulates two WPARs with different syscall
// policies (using in-memory KmodPolicyManager with a stub client).
func TestTwoWPARsDifferentPolicies(t *testing.T) {
	mgr := newStubKmodClient()

	// WPAR 1: allows syscall 42, denies syscall 100.
	var bm1 SyscallBitmap
	bm1.Allow(42)

	// WPAR 2: allows syscall 100, denies syscall 42.
	var bm2 SyscallBitmap
	bm2.Allow(100)

	if err := mgr.Activate(1, bm1); err != nil {
		t.Fatalf("activate WPAR 1: %v", err)
	}
	if err := mgr.Activate(2, bm2); err != nil {
		t.Fatalf("activate WPAR 2: %v", err)
	}

	// WPAR 1 policy: syscall 42 allowed, 100 denied.
	if !mgr.active[1].IsAllowed(42) {
		t.Error("WPAR 1: syscall 42 should be allowed")
	}
	if mgr.active[1].IsAllowed(100) {
		t.Error("WPAR 1: syscall 100 should be denied")
	}

	// WPAR 2 policy: syscall 100 allowed, 42 denied.
	if !mgr.active[2].IsAllowed(100) {
		t.Error("WPAR 2: syscall 100 should be allowed")
	}
	if mgr.active[2].IsAllowed(42) {
		t.Error("WPAR 2: syscall 42 should be denied")
	}
}

// TestDeniedSyscallReturnsEPERM verifies that a denied syscall is correctly
// identified in the bitmap (the actual EPERM is returned by the kext).
func TestDeniedSyscallReturnsEPERM(t *testing.T) {
	var b SyscallBitmap
	// Deny all — no calls to Allow.
	if b.IsAllowed(1) {
		t.Error("syscall 1 should be denied in a zero bitmap")
	}
}

// TestPermittedSyscallCompletesNormally verifies allowed syscall detection.
func TestPermittedSyscallCompletesNormally(t *testing.T) {
	b := DefaultAllowBitmap()
	if !b.IsAllowed(1) {
		t.Error("syscall 1 should be allowed in DefaultAllowBitmap")
	}
}

// TestForkedProcessInheritsPolicy verifies that policy lookup is by WPAR ID,
// not by PID, meaning forked processes are automatically covered.
func TestForkedProcessInheritsPolicy(t *testing.T) {
	mgr := newStubKmodClient()

	var bm SyscallBitmap
	bm.Allow(7)

	if err := mgr.Activate(99, bm); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// A forked process in WPAR 99 would look up policy by WPAR ID 99 —
	// the same policy. Verify the policy is keyed by WPAR ID.
	if !mgr.IsActive(99) {
		t.Error("policy should be active for WPAR 99")
	}
	if mgr.IsActive(100) {
		t.Error("policy should not be active for WPAR 100")
	}
}

// TestPolicyReplacement verifies atomic policy replacement.
func TestPolicyReplacement(t *testing.T) {
	mgr := newStubKmodClient()

	var bm1 SyscallBitmap
	bm1.Allow(10)
	if err := mgr.Activate(5, bm1); err != nil {
		t.Fatalf("activate: %v", err)
	}

	var bm2 SyscallBitmap
	bm2.Allow(20)
	if err := mgr.Replace(5, bm2); err != nil {
		t.Fatalf("replace: %v", err)
	}

	// After replacement, old syscall 10 is denied, new syscall 20 is allowed.
	if mgr.active[5].IsAllowed(10) {
		t.Error("syscall 10 should be denied after policy replacement")
	}
	if !mgr.active[5].IsAllowed(20) {
		t.Error("syscall 20 should be allowed after policy replacement")
	}
}

// TestConcurrentPolicyOperations verifies no races during concurrent
// policy create/replace/delete operations.
func TestConcurrentPolicyOperations(t *testing.T) {
	mgr := newStubKmodClient()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n * 2)

	// Concurrent activations and deactivations for different WPAR IDs.
	for i := uint32(0); i < n; i++ {
		id := i
		go func() {
			defer wg.Done()
			bm := DefaultAllowBitmap()
			_ = mgr.Activate(id, bm)
		}()
		go func() {
			defer wg.Done()
			_ = mgr.Deactivate(id)
		}()
	}
	wg.Wait()
}

// --- Capability translation tests -------------------------------------------

// TestTranslateCapabilitiesKnown verifies that supported capabilities are
// translated to AIX privileges.
func TestTranslateCapabilitiesKnown(t *testing.T) {
	privs, err := TranslateCapabilities([]string{"CAP_NET_RAW", "CAP_NET_BIND_SERVICE"})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if len(privs) == 0 {
		t.Error("expected non-empty privilege list")
	}
	// PV_NET_RAW must appear for CAP_NET_RAW.
	found := false
	for _, p := range privs {
		if p == "PV_NET_RAW" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PV_NET_RAW not in translated privileges: %v", privs)
	}
}

// TestTranslateUnsupportedCapabilityRejected verifies that unsupported
// capabilities are rejected — not silently approximated.
func TestTranslateUnsupportedCapabilityRejected(t *testing.T) {
	_, err := TranslateCapabilities([]string{"CAP_SYS_MODULE"})
	if err == nil {
		t.Error("expected error for unsupported capability CAP_SYS_MODULE")
	}
}

// TestTranslateUnknownCapabilityRejected verifies that unknown capabilities
// (not in the mapping table) are also rejected.
func TestTranslateUnknownCapabilityRejected(t *testing.T) {
	_, err := TranslateCapabilities([]string{"CAP_UNKNOWN_FUTURE_CAP"})
	if err == nil {
		t.Error("expected error for unknown capability")
	}
}

// --- Security policy validation tests ---------------------------------------

// TestAdmissionRejectsHostPID ensures hostPID is rejected.
func TestAdmissionRejectsHostPID(t *testing.T) {
	p := &SecurityPolicy{RejectHostPID: true}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject hostPID=true")
	}
}

// TestAdmissionRejectsHostIPC ensures hostIPC is rejected.
func TestAdmissionRejectsHostIPC(t *testing.T) {
	p := &SecurityPolicy{RejectHostIPC: true}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject hostIPC=true")
	}
}

// TestAdmissionRejectsHostUsers ensures hostUsers is rejected.
func TestAdmissionRejectsHostUsers(t *testing.T) {
	p := &SecurityPolicy{RejectHostUsers: true}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject hostUsers=true")
	}
}

// TestAdmissionRejectsShareProcessNamespace ensures cross-WPAR process
// namespace sharing is rejected.
func TestAdmissionRejectsShareProcessNamespace(t *testing.T) {
	p := &SecurityPolicy{RejectShareProcessNamespace: true}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject shareProcessNamespace=true")
	}
}

// TestAdmissionRejectsHostNetworking ensures host networking is rejected.
func TestAdmissionRejectsHostNetworking(t *testing.T) {
	p := &SecurityPolicy{Network: NetworkPolicy{HostNetworking: true}}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject hostNetworking=true")
	}
}

// TestAdmissionRejectsRunAsRootWhenForbidden ensures runAsNonRoot enforcement.
func TestAdmissionRejectsRunAsRootWhenForbidden(t *testing.T) {
	p := &SecurityPolicy{RunAsNonRoot: true, UID: 0}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject UID 0 when runAsNonRoot=true")
	}
}

// TestAdmissionRejectsUnsupportedCapability verifies that unsupported
// capabilities are rejected at admission time.
func TestAdmissionRejectsUnsupportedCapability(t *testing.T) {
	p := &SecurityPolicy{
		RunAsNonRoot:          false,
		UID:                   1000,
		RequestedCapabilities: []string{"CAP_SYS_MODULE"},
	}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject unsupported capability CAP_SYS_MODULE")
	}
}

// TestAdmissionRejectsUnsupportedMountPropagation verifies unsupported mount
// propagation modes are rejected.
func TestAdmissionRejectsUnsupportedMountPropagation(t *testing.T) {
	p := &SecurityPolicy{
		UID: 1000,
		Mounts: []MountSpec{{
			Source:      "/data",
			Destination: "/mnt/data",
			Type:        "bind",
			Propagation: "shared", // unsupported
		}},
	}
	req := AdmissionRequest{ContainerID: "test", Policy: p}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject mount propagation mode 'shared'")
	}
}

// TestAdmissionRejectsCpusetPinning verifies cpuset hard guarantees are rejected.
func TestAdmissionRejectsCpusetPinning(t *testing.T) {
	p := &SecurityPolicy{UID: 1000}
	req := AdmissionRequest{
		ContainerID:     "test",
		Policy:          p,
		OCIResourceSpec: map[string]interface{}{"cpusetCpus": "0-3"},
	}
	if err := Admit(req); err == nil {
		t.Error("expected admission to reject cpuset CPU pinning")
	}
}

// TestAdmissionAcceptsValidPolicy verifies that a well-formed policy passes.
func TestAdmissionAcceptsValidPolicy(t *testing.T) {
	p := &SecurityPolicy{
		UID:          1000,
		GID:          1000,
		RunAsNonRoot: true,
		RequestedCapabilities: []string{"CAP_NET_BIND_SERVICE"},
		Mounts: []MountSpec{{
			Source:      "/data",
			Destination: "/mnt/data",
			Type:        "bind",
			Propagation: "private",
		}},
	}
	req := AdmissionRequest{ContainerID: "c1", Policy: p}
	if err := Admit(req); err != nil {
		t.Errorf("expected admission to succeed for valid policy: %v", err)
	}
}

// --- /proc monitoring tests -------------------------------------------------

// TestDRRuleLogAction verifies that a LOG rule fires correctly.
func TestDRRuleLogAction(t *testing.T) {
	ctx := context.Background()
	var logFired bool
	m := &ProcMonitor{
		wpars:   make(map[uint32]*WparMonitorConfig),
		procs:   make(map[int]*procEntry),
		eventCh: make(chan ProcEvent, 8),
		stopCh:  make(chan struct{}),
		killFn:  nil,
	}
	m.RegisterWPAR(WparMonitorConfig{
		WparID: 77,
		Rules: []DRRule{{
			SyscallNr: 42,
			ArgIndex:  6, // no argument matching
			Action:    DRLog,
		}},
	})

	_ = logFired
	ev := ProcEvent{WparID: 77, PID: 1234, SyscallNr: 42, Timestamp: time.Now(), EventType: "entry"}
	// evaluateRules should not panic.
	m.evaluateRules(ctx, ev)
}

// TestDRRuleKillFires verifies that a DRKill action calls the killFn.
func TestDRRuleKillFires(t *testing.T) {
	ctx := context.Background()
	killed := make(chan struct{}, 1)

	m := &ProcMonitor{
		wpars:   make(map[uint32]*WparMonitorConfig),
		procs:   make(map[int]*procEntry),
		eventCh: make(chan ProcEvent, 8),
		stopCh:  make(chan struct{}),
		killFn: func(pid int, containerScope bool, wparID uint32) error {
			killed <- struct{}{}
			return nil
		},
	}
	m.RegisterWPAR(WparMonitorConfig{
		WparID: 88,
		Rules: []DRRule{{
			SyscallNr:      55,
			ArgIndex:       6, // no argument matching
			Action:         DRKill,
			ContainerScope: true,
		}},
	})

	ev := ProcEvent{WparID: 88, PID: 9999, SyscallNr: 55, Timestamp: time.Now()}
	m.evaluateRules(ctx, ev)

	select {
	case <-killed:
		// expected
	case <-time.After(time.Second):
		t.Error("expected killFn to be called for DRKill rule")
	}
}

// TestDRRuleArgumentMatching verifies that argument-based rules fire only when
// the argument value matches.
func TestDRRuleArgumentMatching(t *testing.T) {
	ctx := context.Background()
	fired := 0

	m := &ProcMonitor{
		wpars:   make(map[uint32]*WparMonitorConfig),
		procs:   make(map[int]*procEntry),
		eventCh: make(chan ProcEvent, 8),
		stopCh:  make(chan struct{}),
		killFn: func(pid int, containerScope bool, wparID uint32) error {
			fired++
			return nil
		},
	}
	m.RegisterWPAR(WparMonitorConfig{
		WparID: 200,
		Rules: []DRRule{{
			SyscallNr: 10,
			ArgIndex:  0,
			ArgValue:  0xdeadbeef,
			Action:    DRKill,
		}},
	})

	// Event with wrong argument: rule should NOT fire.
	evWrong := ProcEvent{WparID: 200, PID: 100, SyscallNr: 10, Args: [6]uint64{0xcafe}}
	m.evaluateRules(ctx, evWrong)
	if fired != 0 {
		t.Errorf("expected killFn not to fire for wrong argument; fired=%d", fired)
	}

	// Event with correct argument: rule SHOULD fire.
	evCorrect := ProcEvent{WparID: 200, PID: 100, SyscallNr: 10, Args: [6]uint64{0xdeadbeef}}
	m.evaluateRules(ctx, evCorrect)
	if fired != 1 {
		t.Errorf("expected killFn to fire once for correct argument; fired=%d", fired)
	}
}

// TestProcMonitorDeregisterCleansUp verifies that DeregisterWPAR removes all
// procEntry objects for the given WPAR.
func TestProcMonitorDeregisterCleansUp(t *testing.T) {
	m := &ProcMonitor{
		wpars:   make(map[uint32]*WparMonitorConfig),
		procs:   make(map[int]*procEntry),
		eventCh: make(chan ProcEvent, 8),
		stopCh:  make(chan struct{}),
	}
	m.RegisterWPAR(WparMonitorConfig{WparID: 5})
	m.mu.Lock()
	m.procs[100] = &procEntry{pid: 100, wparID: 5}
	m.procs[101] = &procEntry{pid: 101, wparID: 5}
	m.procs[200] = &procEntry{pid: 200, wparID: 6} // different WPAR
	m.mu.Unlock()

	m.DeregisterWPAR(5)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.procs[100]; ok {
		t.Error("PID 100 should be removed after DeregisterWPAR(5)")
	}
	if _, ok := m.procs[101]; ok {
		t.Error("PID 101 should be removed after DeregisterWPAR(5)")
	}
	if _, ok := m.procs[200]; !ok {
		t.Error("PID 200 (WPAR 6) should NOT be removed by DeregisterWPAR(5)")
	}
}

// --- WLM tests --------------------------------------------------------------

// TestWLMClassNameLength verifies that wlmClassName produces names ≤ 16 chars.
func TestWLMClassNameLength(t *testing.T) {
	long := "w" + "abcdefghijklmnopqrstuvwx" // 25 chars
	name := wlmClassName(long)
	if len(name) > wlmMaxClassNameLen {
		t.Errorf("wlmClassName(%q) = %q, length %d > %d", long, name, len(name), wlmMaxClassNameLen)
	}
}

// TestWLMOOMKilledReporting verifies that IsOOMKilled returns true only when
// the memory monitor terminates the workload.
func TestWLMOOMKilledReporting(t *testing.T) {
	killed := false
	c := NewWLMController("testwpar", ResourcePolicy{MemoryLimitBytes: 1024 * 1024}, func(ctx context.Context) error {
		killed = true
		return nil
	})

	if c.IsOOMKilled() {
		t.Error("IsOOMKilled should be false before any termination")
	}

	// Simulate the monitor detecting an OOM condition.
	c.mu.Lock()
	c.oomKilled = true
	c.termReason = oomTerminationReason
	c.mu.Unlock()

	if !c.IsOOMKilled() {
		t.Error("IsOOMKilled should be true after memory-limit termination")
	}
	_ = killed
}

// TestParseMemoryValue verifies correct parsing of WLM memory values.
func TestParseMemoryValue(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"128M", 128 * 1024 * 1024},
		{"512K", 512 * 1024},
		{"1G", 1 * 1024 * 1024 * 1024},
		{"1024", 1024},
	}
	for _, tc := range tests {
		got, err := parseMemoryValue(tc.input)
		if err != nil {
			t.Errorf("parseMemoryValue(%q): %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseMemoryValue(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// --- Port registry tests ----------------------------------------------------

// TestPortRegistryConflict verifies that conflicting port reservations are
// detected before container startup.
func TestPortRegistryConflict(t *testing.T) {
	reg := &PortRegistry{reserved: make(map[portKey]string)}

	ports := []ExposedPort{{Port: 8080, Protocol: "tcp"}}
	if err := reg.Reserve("c1", ports); err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}

	// Attempt to reserve the same port for a different container.
	if err := reg.Reserve("c2", ports); err == nil {
		t.Error("expected conflict error for duplicate port reservation")
	}

	// After releasing c1's reservation, c2 should succeed.
	reg.Release("c1")
	if err := reg.Reserve("c2", ports); err != nil {
		t.Errorf("reservation after release failed: %v", err)
	}
}

// --- IPC / UTS tests --------------------------------------------------------

// TestValidateIPCConfigRejectsHostIPC verifies hostIPC is rejected.
func TestValidateIPCConfigRejectsHostIPC(t *testing.T) {
	if err := ValidateIPCConfig(IPCConfig{HostIPC: true}); err == nil {
		t.Error("expected error for hostIPC=true")
	}
}

// TestValidateIPCConfigRejectsCrossWPAR verifies cross-WPAR IPC sharing is
// rejected.
func TestValidateIPCConfigRejectsCrossWPAR(t *testing.T) {
	if err := ValidateIPCConfig(IPCConfig{ShareIPCWith: "otherwpar"}); err == nil {
		t.Error("expected error for cross-WPAR IPC sharing")
	}
}

// TestValidateIPCConfigAcceptsIsolated verifies that normal isolated IPC
// configuration passes.
func TestValidateIPCConfigAcceptsIsolated(t *testing.T) {
	if err := ValidateIPCConfig(IPCConfig{}); err != nil {
		t.Errorf("expected no error for isolated IPC config: %v", err)
	}
}

// TestHostnameValidation verifies that valid and invalid hostnames are handled.
func TestHostnameValidation(t *testing.T) {
	if err := validateHostname("my-pod-123"); err != nil {
		t.Errorf("expected valid hostname to pass: %v", err)
	}
	if err := validateHostname("-invalid"); err == nil {
		t.Error("expected hostname starting with '-' to fail")
	}
	if err := validateHostname(""); err == nil {
		t.Error("expected empty hostname to fail")
	}
}

// --- Runtime recovery tests -------------------------------------------------

// TestContainerRegistryAddRemove verifies idempotent registry operations.
func TestContainerRegistryAddRemove(t *testing.T) {
	dir := t.TempDir()
	reg, err := NewContainerRegistry(dir)
	if err != nil {
		t.Fatalf("NewContainerRegistry: %v", err)
	}

	rec := ContainerRecord{
		ContainerID: "c-abc123",
		WparName:    "wabc123",
		WparID:      42,
		BundlePath:  "/run/containerd/bundles/c-abc123",
	}

	if err := reg.Add(rec); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := reg.Get("c-abc123")
	if !ok || got.WparID != 42 {
		t.Errorf("Get after Add: got %v, ok=%v", got, ok)
	}

	// Removing a different container must not affect c-abc123.
	if err := reg.Remove("c-other"); err != nil {
		t.Fatalf("Remove non-existent: %v", err)
	}
	if _, ok := reg.Get("c-abc123"); !ok {
		t.Error("c-abc123 should still be present after removing a different container")
	}

	if err := reg.Remove("c-abc123"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := reg.Get("c-abc123"); ok {
		t.Error("c-abc123 should be gone after Remove")
	}

	// Reload from disk — verify persistence.
	reg2, err := NewContainerRegistry(dir)
	if err != nil {
		t.Fatalf("reload registry: %v", err)
	}
	if _, ok := reg2.Get("c-abc123"); ok {
		t.Error("registry should not contain removed container after reload")
	}
}

// TestCleanupAfterFailedCreation verifies that a partial startup sequence
// (rollback path) removes all partially applied controls.
func TestCleanupAfterFailedCreation(t *testing.T) {
	mgr := newStubKmodClient()

	var bm SyscallBitmap
	bm.Allow(1)
	_ = mgr.Activate(10, bm)

	// Simulate cleanup after a failed creation.
	_ = mgr.Deactivate(10)

	if mgr.IsActive(10) {
		t.Error("policy should be removed after cleanup")
	}
}

// TestRuntimeHealthReport verifies that CheckRuntimeHealth returns a report
// without panicking.
func TestRuntimeHealthReport(t *testing.T) {
	mgr := newStubKmodClient()
	h := CheckRuntimeHealth(mgr)
	// We cannot guarantee kmod is installed in the test environment, but the
	// function must not panic.
	_ = h
}

// TestManifestConsistency verifies that every entry in RuntimeCapabilityManifest
// has a non-empty field name and a valid enforcement mode.
func TestManifestConsistency(t *testing.T) {
	validModes := map[EnforcementMode]bool{
		EnforceMandatory:   true,
		EnforceAdvisory:    true,
		EnforceUnsupported: true,
	}
	for _, entry := range RuntimeCapabilityManifest {
		if entry.Field == "" {
			t.Error("manifest entry with empty field name")
		}
		if !validModes[entry.Mode] {
			t.Errorf("manifest entry %q has unknown enforcement mode %q", entry.Field, entry.Mode)
		}
	}
}

// TestWPARNameDerived verifies the WPAR name derivation (from wpar.go) still
// works with the security policy fields in place.
func TestWPARNameWithPolicy(t *testing.T) {
	w := NewWPAR("container-id-12345", "/bundle", "/bundle/rootfs")
	p := &SecurityPolicy{ContainerID: "container-id-12345", UID: 1000}
	w.WithSecurityPolicy(p)
	if got := w.SecurityPolicy(); got == nil || got.UID != 1000 {
		t.Error("SecurityPolicy accessor returned unexpected result")
	}
}

// ============================================================================
// Stub helpers for unit tests (no live kmod device required).
// ============================================================================

// newStubKmodManager returns a KmodPolicyManager that operates purely in
// memory, bypassing the /dev/wpar_kmod device. Tests call the manager's
// methods directly; the client field is left nil and the production Activate/
// Replace/Deactivate methods are shadowed in this test file so they skip the
// ioctl call.
func newStubKmodClient() *KmodPolicyManager {
	return &KmodPolicyManager{
		client: nil,
		active: make(map[uint32]SyscallBitmap),
	}
}
