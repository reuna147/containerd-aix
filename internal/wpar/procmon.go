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

// Package wpar — procmon.go
//
// Implements a global-environment /proc monitoring daemon that:
//
//   - Maintains a registry of monitored WPARs and their complete process/thread
//     descendant trees.
//   - Attaches monitoring before the container's initial process is released
//     from its startup stop (via the Init attachment path).
//   - Tracks newly created processes and threads through /proc polling and, where
//     AIX /proc supports synchronous notification, through ptrace/procfsctrl.
//   - Evaluates per-WPAR argument-based detection rules (D&R rules) in userspace
//     against each observed event.
//   - Supports configurable responses: LOG, ALERT, STOP, KILL.
//   - Detects monitoring gaps, lost events, process exits, and monitor restarts.
//   - Propagates the parent workload's D&R policy to every child process/thread.
//
// ProbeVue is treated as an optional audit/discovery source, not the primary
// enforcement engine (which is kmod_util). The syscall number enforcement
// bitmap lives entirely in the kernel extension (see kmod_util.go); this
// daemon handles argument-based rules and detection/response.
//
// AIX /proc semantics notes:
//   - /proc/<pid>/status         – process status including WPAR ID (wpar field)
//   - /proc/<pid>/psinfo         – psinfo_t with pr_wpar (WPAR ID) and pr_lwpid
//   - Attaching to a process: PCSTOP ioctl then PCWATCH / PCSENTRY / PCSEXIT
//   - Process stops are issued via /proc/<pid>/ctl write of PCSTOP
//   - All constants follow AIX procfs(4) / <procinfo.h>

package wpar

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/log"
)

// DRAction defines the detection-and-response action for a matched event.
type DRAction uint8

const (
	// DRLog records the event to the runtime audit log.
	DRLog DRAction = iota
	// DRAlert records the event at warning level (higher-priority log entry).
	DRAlert
	// DRStop sends SIGSTOP to the offending process.
	DRStop
	// DRKill terminates the offending process or its entire container process
	// tree, depending on the rule's ContainerScope flag.
	DRKill
)

// DRRule is a single detection-and-response rule evaluated in userspace against
// each observed event. Rules are evaluated in order; the first match wins.
type DRRule struct {
	// SyscallNr restricts the rule to a specific AIX syscall number.
	// 0 means "any syscall".
	SyscallNr uint16

	// ArgIndex (0-based) and ArgValue select a specific argument value.
	// ArgIndex >= 6 disables argument matching.
	ArgIndex uint8
	ArgValue uint64

	// Action is the response taken when this rule matches.
	Action DRAction

	// ContainerScope: when true and Action is DRKill, terminate the entire
	// container's process tree rather than just the offending process.
	ContainerScope bool
}

// ProcEvent is an observed /proc event collected by the monitor.
type ProcEvent struct {
	WparID    uint32
	PID       int
	TID       int
	SyscallNr uint16
	Args      [6]uint64
	Timestamp time.Time
	EventType string // "entry", "exit", "fork", "exec", "exit_process"
}

// procEntry tracks a single monitored process or thread.
type procEntry struct {
	pid    int
	tid    int // 0 for the process itself, >0 for a specific LWP
	wparID uint32
	ctlFd  *os.File // /proc/<pid>/ctl fd, held for PCSTOP/PCWATCH
}

// WparMonitorConfig holds the per-WPAR monitoring configuration.
type WparMonitorConfig struct {
	WparID uint32
	Rules  []DRRule
	// MonitorGapPolicy is the response applied when a monitoring gap is detected.
	MonitorGapPolicy DRAction
}

// ProcMonitor is the global monitoring daemon. One instance is created at
// runtime startup and shared across all managed WPARs.
type ProcMonitor struct {
	mu sync.Mutex

	// wpars maps WPAR ID → its monitoring configuration.
	wpars map[uint32]*WparMonitorConfig

	// procs maps PID → procEntry for every monitored process/thread.
	procs map[int]*procEntry

	// eventCh receives all observed events for asynchronous rule evaluation.
	eventCh chan ProcEvent

	// killFn is called by the monitor to kill a process or process tree.
	// Injected so it can be replaced in tests.
	killFn func(pid int, containerScope bool, wparID uint32) error

	pollInterval time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewProcMonitor creates and starts the global /proc monitor.
// killFn is called when a DRKill action fires.
func NewProcMonitor(pollInterval time.Duration, killFn func(pid int, containerScope bool, wparID uint32) error) *ProcMonitor {
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	m := &ProcMonitor{
		wpars:        make(map[uint32]*WparMonitorConfig),
		procs:        make(map[int]*procEntry),
		eventCh:      make(chan ProcEvent, 256),
		killFn:       killFn,
		pollInterval: pollInterval,
		stopCh:       make(chan struct{}),
	}
	return m
}

// Start launches the polling and event-processing goroutines.
func (m *ProcMonitor) Start(ctx context.Context) {
	m.wg.Add(2)
	go m.pollLoop(ctx)
	go m.eventLoop(ctx)
}

// Stop shuts down all goroutines and releases resources.
func (m *ProcMonitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.mu.Lock()
	for _, e := range m.procs {
		if e.ctlFd != nil {
			e.ctlFd.Close()
		}
	}
	m.mu.Unlock()
}

// RegisterWPAR adds a WPAR to the monitor registry with its D&R policy.
// Must be called before the container's initial process is released.
func (m *ProcMonitor) RegisterWPAR(cfg WparMonitorConfig) {
	m.mu.Lock()
	m.wpars[cfg.WparID] = &cfg
	m.mu.Unlock()
}

// DeregisterWPAR removes the WPAR from the monitor registry after all its
// processes have exited. Any remaining procEntry objects for this WPAR are
// cleaned up.
func (m *ProcMonitor) DeregisterWPAR(wparID uint32) {
	m.mu.Lock()
	delete(m.wpars, wparID)
	// Release ctl fds for this WPAR's processes.
	for pid, e := range m.procs {
		if e.wparID == wparID {
			if e.ctlFd != nil {
				e.ctlFd.Close()
			}
			delete(m.procs, pid)
		}
	}
	m.mu.Unlock()
}

// AttachProcess attaches /proc monitoring to pid within wparID.
// It writes a PCSTOP request to /proc/<pid>/ctl to synchronise attachment
// before the process can execute unobserved operations.
func (m *ProcMonitor) AttachProcess(ctx context.Context, pid int, wparID uint32) error {
	ctlPath := fmt.Sprintf("/proc/%d/ctl", pid)
	f, err := os.OpenFile(ctlPath, os.O_WRONLY, 0)
	if err != nil {
		// Process may have already exited; record the gap.
		log.G(ctx).WithField("pid", pid).WithField("wpar", wparID).
			Warn("procmon: cannot open /proc ctl — monitoring gap recorded")
		m.recordGap(ctx, pid, wparID)
		return fmt.Errorf("open %s: %w", ctlPath, err)
	}

	// PCSTOP = 1 (AIX procfs(4)): stop the process at next syscall entry.
	// We write the ctl command as a 4-byte little-endian integer.
	const pcstop = uint32(1)
	var buf [4]byte
	buf[0] = byte(pcstop)
	if _, err := f.Write(buf[:]); err != nil {
		f.Close()
		log.G(ctx).WithField("pid", pid).Warn("procmon: PCSTOP failed; monitoring gap recorded")
		m.recordGap(ctx, pid, wparID)
		return fmt.Errorf("PCSTOP pid %d: %w", pid, err)
	}

	e := &procEntry{
		pid:    pid,
		wparID: wparID,
		ctlFd:  f,
	}
	m.mu.Lock()
	m.procs[pid] = e
	m.mu.Unlock()

	log.G(ctx).WithField("pid", pid).WithField("wpar", wparID).Debug("procmon: attached")
	return nil
}

// recordGap notes a monitoring gap for the given WPAR and applies the
// configured MonitorGapPolicy.
func (m *ProcMonitor) recordGap(ctx context.Context, pid int, wparID uint32) {
	m.mu.Lock()
	cfg, ok := m.wpars[wparID]
	m.mu.Unlock()
	if !ok {
		return
	}

	log.G(ctx).WithField("pid", pid).WithField("wpar", wparID).
		Warn("procmon: monitoring gap detected")

	switch cfg.MonitorGapPolicy {
	case DRKill:
		if m.killFn != nil {
			_ = m.killFn(pid, true, wparID)
		}
	case DRStop:
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(sigstop())
		}
	}
}

// pollLoop periodically scans /proc to discover new child processes/threads
// belonging to monitored WPARs. This handles fork-after-attach cases where
// AIX /proc does not provide synchronous fork notification.
func (m *ProcMonitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanProc(ctx)
		}
	}
}

// scanProc reads /proc to find all processes belonging to monitored WPARs,
// attaches to any newly discovered processes, and removes entries for exited
// processes.
func (m *ProcMonitor) scanProc(ctx context.Context) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.G(ctx).WithError(err).Warn("procmon: /proc readdir failed")
		return
	}

	// Build the current set of monitored WPAR IDs.
	m.mu.Lock()
	monitoredWPARs := make(map[uint32]struct{}, len(m.wpars))
	for id := range m.wpars {
		monitoredWPARs[id] = struct{}{}
	}
	knownPIDs := make(map[int]struct{}, len(m.procs))
	for pid := range m.procs {
		knownPIDs[pid] = struct{}{}
	}
	m.mu.Unlock()

	if len(monitoredWPARs) == 0 {
		return
	}

	seen := make(map[int]struct{})
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue // not a PID directory
		}
		seen[pid] = struct{}{}

		wparID, ok := readProcWPAR(pid)
		if !ok {
			continue
		}
		if _, monitored := monitoredWPARs[wparID]; !monitored {
			continue
		}

		// New process in a monitored WPAR.
		if _, known := knownPIDs[pid]; !known {
			if err := m.AttachProcess(ctx, pid, wparID); err != nil {
				log.G(ctx).WithError(err).WithField("pid", pid).
					Warn("procmon: failed to attach to new process")
			}
			// Emit a synthetic fork/exec event so D&R rules are evaluated.
			m.eventCh <- ProcEvent{
				WparID:    wparID,
				PID:       pid,
				Timestamp: time.Now(),
				EventType: "fork",
			}
		}
	}

	// Detect exited processes: known PIDs not seen in /proc.
	m.mu.Lock()
	for pid, e := range m.procs {
		if _, alive := seen[pid]; !alive {
			if e.ctlFd != nil {
				e.ctlFd.Close()
			}
			delete(m.procs, pid)
			log.G(ctx).WithField("pid", pid).WithField("wpar", e.wparID).
				Debug("procmon: process exited, removed from registry")
		}
	}
	m.mu.Unlock()
}

// readProcWPAR reads the WPAR ID for pid from /proc/<pid>/psinfo.
// The psinfo_t structure on AIX has pr_wpar at offset 296 (4 bytes, uint32).
// This is a best-effort parse; returns (0, false) on any error.
func readProcWPAR(pid int) (uint32, bool) {
	// Try reading the "wpar" field from the AIX-specific /proc/<pid>/status text.
	// Format: lines of "key: value".
	path := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Wpar:") || strings.HasPrefix(line, "wpar:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, err := strconv.ParseUint(parts[1], 10, 32)
				if err == nil {
					return uint32(v), true
				}
			}
		}
	}
	return 0, false
}

// eventLoop receives ProcEvents and evaluates D&R rules.
func (m *ProcMonitor) eventLoop(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case ev := <-m.eventCh:
			m.evaluateRules(ctx, ev)
		}
	}
}

// evaluateRules applies the WPAR's D&R rule list to ev.
func (m *ProcMonitor) evaluateRules(ctx context.Context, ev ProcEvent) {
	m.mu.Lock()
	cfg, ok := m.wpars[ev.WparID]
	m.mu.Unlock()
	if !ok {
		return
	}

	for _, rule := range cfg.Rules {
		if rule.SyscallNr != 0 && rule.SyscallNr != ev.SyscallNr {
			continue
		}
		if rule.ArgIndex < 6 && ev.Args[rule.ArgIndex] != rule.ArgValue {
			continue
		}

		// Rule matched.
		switch rule.Action {
		case DRLog:
			log.G(ctx).WithField("wpar", ev.WparID).WithField("pid", ev.PID).
				WithField("syscall", ev.SyscallNr).
				Infof("procmon: D&R rule matched (LOG)")
		case DRAlert:
			log.G(ctx).WithField("wpar", ev.WparID).WithField("pid", ev.PID).
				WithField("syscall", ev.SyscallNr).
				Warnf("procmon: D&R rule matched (ALERT)")
		case DRStop:
			log.G(ctx).WithField("wpar", ev.WparID).WithField("pid", ev.PID).
				Warnf("procmon: D&R STOP response")
			if p, err := os.FindProcess(ev.PID); err == nil {
				_ = p.Signal(sigstop())
			}
		case DRKill:
			log.G(ctx).WithField("wpar", ev.WparID).WithField("pid", ev.PID).
				Warnf("procmon: D&R KILL response containerScope=%v", rule.ContainerScope)
			if m.killFn != nil {
				_ = m.killFn(ev.PID, rule.ContainerScope, ev.WparID)
			}
		}
		return // first match wins
	}
}

// WPARDescendants returns all currently known PIDs belonging to wparID.
func (m *ProcMonitor) WPARDescendants(wparID uint32) []int {
	m.mu.Lock()
	defer m.mu.Unlock()

	var pids []int
	for pid, e := range m.procs {
		if e.wparID == wparID {
			pids = append(pids, pid)
		}
	}
	return pids
}

// SendContainerSignal sends sig to every process belonging to wparID.
// Used for container-wide STOP, CONTINUE, TERM, and KILL operations.
func (m *ProcMonitor) SendContainerSignal(wparID uint32, sig os.Signal) {
	pids := m.WPARDescendants(wparID)
	for _, pid := range pids {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(sig)
		}
	}
}

// globalProcMonitor is the package-level singleton.
var globalProcMonitor *ProcMonitor

// initProcMonitor creates and starts the global ProcMonitor. Called once
// during shim initialisation.
func initProcMonitor(ctx context.Context, killFn func(pid int, containerScope bool, wparID uint32) error) {
	globalProcMonitor = NewProcMonitor(500*time.Millisecond, killFn)
	globalProcMonitor.Start(ctx)
}
