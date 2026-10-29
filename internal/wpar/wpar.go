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

// Package wpar implements a containerd shim runtime for AIX Workload Partitions
// (WPARs). WPARs are AIX's native lightweight isolation primitive, analogous to
// Linux containers. This package provides the low-level lifecycle operations by
// shelling out to the standard AIX WPAR management tools:
//
//   mkwpar  – create a new WPAR
//   startwpar – start a previously created WPAR
//   stopwpar  – stop a running WPAR
//   rmwpar    – destroy a WPAR
//   lswpar    – query WPAR state
//
// Process execution inside WPARs uses clogin(1) -R.
package wpar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
)

// State represents the lifecycle state of a WPAR as reported by lswpar.
type State int

const (
	StateUnknown State = iota
	StateActive        // lswpar "A" – running
	StateDown          // lswpar "D" – stopped / defined but not running
)

// String returns the lswpar status letter.
func (s State) String() string {
	switch s {
	case StateActive:
		return "A"
	case StateDown:
		return "D"
	default:
		return "?"
	}
}

// wparStateFile is a small JSON blob persisted next to the OCI bundle so the
// shim can recover state after a restart.
type wparStateFile struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Pid      uint32    `json:"pid"`
	ExitCode uint32    `json:"exit_code"`
	ExitedAt time.Time `json:"exited_at,omitempty"`
	// RootDir is the directory we unpacked the image into.
	RootDir string `json:"root_dir,omitempty"`
}

// WPAR represents a single managed AIX Workload Partition.
type WPAR struct {
	mu sync.Mutex

	id         string // containerd task ID
	name       string // AIX WPAR name (max 25 chars, derived from id)
	bundlePath string
	rootdir    string

	pid      uint32
	state    State
	exitCode uint32
	exitedAt time.Time

	waiters []chan struct{} // closed when the WPAR transitions to StateDown
}

// wparName derives a valid AIX WPAR name from a containerd task ID.
//
// AIX WPAR names must be ≤25 characters (not 31 as the mkwpar man page implies
// for some fields — 0960-347 fires at 26). They may contain [a-zA-Z0-9_-] but
// must not start with a digit. We prefix a letter to handle hex IDs that start
// with a digit, then use the last 24 characters of the sanitised ID to
// maximise uniqueness.
func wparName(id string) string {
	// Sanitise: replace non-[a-zA-Z0-9_-] with underscores.
	var b strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	s := b.String()

	// Ensure the first character is a letter by prefixing "w".
	// Total budget: 25 chars. Prefix "w" + up to 24 chars from the end.
	const maxLen = 25
	const prefix = "w"
	tail := s
	if len(tail) > maxLen-len(prefix) {
		tail = tail[len(tail)-(maxLen-len(prefix)):]
	}
	return prefix + tail
}

// statePath returns the path to the persisted state JSON file.
func statePath(bundlePath string) string {
	return filepath.Join(bundlePath, "wpar-state.json")
}

// NewWPAR constructs a WPAR object from scratch (Create path).
func NewWPAR(id, bundlePath, rootdir string) *WPAR {
	return &WPAR{
		id:         id,
		name:       wparName(id),
		bundlePath: bundlePath,
		rootdir:    rootdir,
		state:      StateDown,
	}
}

// LoadWPAR restores a WPAR object from a persisted state file.
func LoadWPAR(bundlePath string) (*WPAR, error) {
	data, err := os.ReadFile(statePath(bundlePath))
	if err != nil {
		return nil, fmt.Errorf("read wpar state: %w", err)
	}
	var sf wparStateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("unmarshal wpar state: %w", err)
	}
	w := &WPAR{
		id:         sf.ID,
		name:       wparName(sf.ID),
		bundlePath: bundlePath,
		rootdir:    sf.RootDir,
		pid:        sf.Pid,
		exitCode:   sf.ExitCode,
		exitedAt:   sf.ExitedAt,
	}
	// Reconcile with live lswpar state.
	s, err := lswparState(w.name)
	if err != nil {
		// WPAR may not exist any more (e.g. after reboot).
		w.state = StateDown
	} else {
		w.state = s
	}
	return w, nil
}

// ID returns the containerd task ID.
func (w *WPAR) ID() string { return w.id }

// Name returns the AIX WPAR name.
func (w *WPAR) Name() string { return w.name }

// Pid returns the stub PID used to represent this WPAR to containerd.
func (w *WPAR) Pid() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pid
}

// CurrentState returns the current lifecycle state.
func (w *WPAR) CurrentState() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// ExitStatus returns the exit code and exit time (only valid after the WPAR has stopped).
func (w *WPAR) ExitStatus() (uint32, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exitCode, w.exitedAt
}

// saveState persists the current state to disk.
// Caller must not hold w.mu.
func (w *WPAR) saveState() error {
	w.mu.Lock()
	sf := wparStateFile{
		ID:       w.id,
		Name:     w.name,
		Pid:      w.pid,
		ExitCode: w.exitCode,
		ExitedAt: w.exitedAt,
		RootDir:  w.rootdir,
	}
	w.mu.Unlock()

	data, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(w.bundlePath), data, 0600)
}

// Create allocates the WPAR via mkwpar.
//
// We use "mkwpar -n NAME -d BASEDIR -M directory=/ vfs=directory" which makes
// "/" a plain directory mount instead of a new logical volume, then copy the
// image rootfs in with pax. This avoids the ~8-minute populate overhead.
//
// mkwpar constraints:
//   - The -d base directory must be empty (not the image rootfs directly).
//   - The parent of -d must be mode 0700.
//   - WPAR names are at most 25 bytes and must not start with a digit.
//   - Do NOT pass -N (that is the network flag, not "don't start").
//   - mkwpar does not start the WPAR unless given -s.
func (w *WPAR) Create(ctx context.Context) error {
	w.mu.Lock()
	if w.state != StateDown {
		w.mu.Unlock()
		return fmt.Errorf("wpar %s is not in down state (state=%s)", w.name, w.state)
	}
	w.mu.Unlock()

	// The base directory for the WPAR must be empty.
	// We create a dedicated base directory alongside rootdir.
	baseDir := w.rootdir + "-wpar"
	if err := os.MkdirAll(filepath.Dir(baseDir), 0700); err != nil {
		return fmt.Errorf("create wpar parent dir: %w", err)
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("create wpar base dir: %w", err)
	}

	// mkwpar -n NAME -d BASEDIR -M directory=/ vfs=directory
	// This creates the WPAR with "/" as a plain directory mount (no LV).
	// The image contents must be copied in separately (done by the shim's
	// Create caller before calling us — rootdir contains the unpacked rootfs).
	args := []string{"-n", w.name, "-d", baseDir, "-M", "directory=/ vfs=directory"}
	if err := runCmdAt(ctx, "/", "mkwpar", args...); err != nil {
		return fmt.Errorf("mkwpar: %w", err)
	}

	// Copy the image rootfs into the WPAR's base directory with pax.
	// pax -rw -pe requires the destination to exist (it does: baseDir).
	if err := copyRootfs(ctx, w.rootdir, baseDir); err != nil {
		return fmt.Errorf("copy rootfs to wpar base: %w", err)
	}

	return w.saveState()
}

// copyRootfs copies src into dst using "pax -rw -pe" (preserving metadata).
func copyRootfs(ctx context.Context, src, dst string) error {
	// pax -rw -pe . <dst> (run from src)
	cmd := exec.CommandContext(ctx, "pax", "-rw", "-pe", ".", dst)
	cmd.Dir = src
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pax -rw -pe . %s: %w\n%s", dst, err, out.String())
	}
	return nil
}

// Start activates the WPAR via startwpar, then launches the container process
// via clogin(1) inside the running WPAR.
func (w *WPAR) Start(ctx context.Context, specArgs []string, specEnv []string, specCwd string, stdoutFIFO, stderrFIFO string) error {
	w.mu.Lock()
	w.mu.Unlock()

	if err := runCmdAt(ctx, "/", "startwpar", w.name); err != nil {
		return fmt.Errorf("startwpar: %w", err)
	}

	w.mu.Lock()
	w.state = StateActive
	w.mu.Unlock()

	if err := w.saveState(); err != nil {
		return err
	}

	// Run the container process inside the WPAR with clogin -R.
	// clogin joins its arguments into a single shell command, so every
	// argument must be shell-quoted.
	pid, err := w.runProcess(ctx, specArgs, specEnv, specCwd, stdoutFIFO, stderrFIFO)
	if err != nil {
		return fmt.Errorf("run container process: %w", err)
	}

	w.mu.Lock()
	w.pid = pid
	w.mu.Unlock()

	return w.saveState()
}

// runProcess launches the container command inside the WPAR via clogin(1).
// It returns the PID of the clogin process (used as the task PID).
//
// clogin quirks (from the test report):
//   - clogin joins all arguments into one string and passes it to a shell.
//     Every argument must be shell-quoted.
//   - stdin does not pass through (the program inside gets EBADF). We connect
//     /dev/null.
//   - We wire stdout and stderr to containerd's FIFOs.
//   - clogin passes the exit code through; for signal death we report 128+sig.
func (w *WPAR) runProcess(ctx context.Context, args []string, env []string, cwd string, stdoutFIFO, stderrFIFO string) (uint32, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("runProcess: no command specified")
	}

	// Build the shell command: "env VAR=VAL ... sh -c 'cd CWD && CMD ARGS...'"
	// We shell-quote every argument individually.
	var shellCmd strings.Builder

	// Set environment variables before the command.
	for _, e := range env {
		shellCmd.WriteString(shellQuote(e))
		shellCmd.WriteByte(' ')
	}

	// Change working directory if specified.
	if cwd != "" {
		shellCmd.WriteString("cd ")
		shellCmd.WriteString(shellQuote(cwd))
		shellCmd.WriteString(" && ")
	}

	for i, a := range args {
		if i > 0 {
			shellCmd.WriteByte(' ')
		}
		shellCmd.WriteString(shellQuote(a))
	}

	// clogin -R WPAR SHELLCMD
	cloginArgs := []string{"-R", w.name, shellCmd.String()}

	cmd := exec.CommandContext(ctx, "clogin", cloginArgs...)
	cmd.Dir = "/"
	cmd.Stdin = nil // /dev/null inherited from process

	// Wire stdout/stderr to containerd's FIFOs.
	if stdoutFIFO != "" {
		f, err := os.OpenFile(stdoutFIFO, os.O_WRONLY, 0)
		if err != nil {
			return 0, fmt.Errorf("open stdout fifo %s: %w", stdoutFIFO, err)
		}
		cmd.Stdout = f
		defer f.Close()
	}
	if stderrFIFO != "" {
		f, err := os.OpenFile(stderrFIFO, os.O_WRONLY, 0)
		if err != nil {
			return 0, fmt.Errorf("open stderr fifo %s: %w", stderrFIFO, err)
		}
		cmd.Stderr = f
		defer f.Close()
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("clogin: %w", err)
	}

	pid := uint32(cmd.Process.Pid)

	// Wait for clogin in the background; close the WPAR watchers when done.
	go w.waitForProcess(ctx, cmd)

	return pid, nil
}

// waitForProcess waits for the clogin process to exit, records the exit code,
// and notifies all waiters.
func (w *WPAR) waitForProcess(ctx context.Context, cmd *exec.Cmd) {
	err := cmd.Wait()

	var exitCode uint32
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// For signal death, report 128 + signal number.
			if status, ok := exitErr.Sys().(interface{ Signal() int }); ok {
				exitCode = uint32(128 + status.Signal())
			} else {
				exitCode = uint32(exitErr.ExitCode())
			}
		}
	}

	w.mu.Lock()
	w.state = StateDown
	w.exitCode = exitCode
	if w.exitedAt.IsZero() {
		w.exitedAt = time.Now()
	}
	waiters := w.waiters
	w.waiters = nil
	w.mu.Unlock()

	_ = w.saveState()
	for _, ch := range waiters {
		close(ch)
	}

	log.G(ctx).WithField("id", w.id).WithField("exit_code", exitCode).Debug("wpar: container process exited")
}

// shellQuote returns a safely shell-quoted version of s using single quotes.
func shellQuote(s string) string {
	// Replace every ' with '\'' to handle single quotes inside the string.
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Kill sends a signal to the WPAR. SIGKILL / SIGTERM stop the whole partition;
// other signals are forwarded to the clogin process.
func (w *WPAR) Kill(ctx context.Context, signal uint32, all bool) error {
	w.mu.Lock()
	state := w.state
	name := w.name
	w.mu.Unlock()

	if state != StateActive {
		return errdefs.ErrNotFound
	}

	// For SIGKILL / SIGTERM, stop the whole partition — the watchUntilDown
	// goroutine (or waitForProcess) will see the process exit and notify waiters.
	const sigkill = 9
	const sigterm = 15
	if signal == sigkill || signal == sigterm {
		if err := runCmdAt(ctx, "/", "stopwpar", name); err != nil {
			return fmt.Errorf("stopwpar: %w", err)
		}
		return nil
	}

	// Forward other signals to the clogin/init process directly.
	w.mu.Lock()
	pid := w.pid
	w.mu.Unlock()
	if pid == 0 {
		return fmt.Errorf("no known PID for WPAR %s", name)
	}
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	// syscall.Signal is an int on AIX.
	return p.Signal(syscallSignal(signal))
}

// Stop issues stopwpar. We do NOT call this before rmwpar — rmwpar -F does its
// own stop, and a double stop leaves the WPAR Broken.
func (w *WPAR) Stop(ctx context.Context) error {
	w.mu.Lock()
	name := w.name
	w.mu.Unlock()

	// Run from "/" so the command does not inherit the bundle dir (issue 16).
	if err := runCmdAt(ctx, "/", "stopwpar", name); err != nil {
		return fmt.Errorf("stopwpar: %w", err)
	}
	return nil
}

// Delete destroys the WPAR via rmwpar -F and removes the persisted state file.
// All WPAR commands run from "/" (issue 16) and with a background context that
// ignores the caller's cancellation (issue 15).
func (w *WPAR) Delete(ctx context.Context) error {
	w.mu.Lock()
	name := w.name
	baseDir := w.rootdir + "-wpar"
	w.mu.Unlock()

	// rmwpar -F does its own stop — do NOT stopwpar first (double stop breaks
	// things). Run from "/" so it does not inherit the bundle dir.
	bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := runCmdAt(bgCtx, "/", "rmwpar", "-F", name); err != nil {
		// If the WPAR is already gone, that is fine.
		log.G(ctx).WithError(err).Warn("wpar: rmwpar -F; WPAR may already be gone")
	}

	// Remove the base directory created for this WPAR.
	_ = os.RemoveAll(baseDir)

	_ = os.Remove(statePath(w.bundlePath))
	return nil
}

// Wait returns a channel that is closed when the WPAR transitions to StateDown.
func (w *WPAR) Wait() <-chan struct{} {
	ch := make(chan struct{})
	w.mu.Lock()
	if w.state == StateDown {
		close(ch)
	} else {
		w.waiters = append(w.waiters, ch)
	}
	w.mu.Unlock()
	return ch
}

// ---- helpers ----------------------------------------------------------------

// runCmdAt executes an external WPAR management command from the given working
// directory (always "/" for safety), logging stdout/stderr.
func runCmdAt(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	log.G(ctx).WithField("cmd", append([]string{name}, args...)).Debug("running wpar command")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, out.String())
	}
	return nil
}

// runCmd is a convenience wrapper that runs from "/".
func runCmd(ctx context.Context, name string, args ...string) error {
	return runCmdAt(ctx, "/", name, args...)
}

// lswparState queries lswpar for the named WPAR's state.
//
// The correct invocation is:
//
//	lswpar -c -q -a name,state NAME
//
// which outputs a single "name:state" line, e.g. "mywpar:A".
// "lswpar -n NAME" is NOT a valid flag combination.
func lswparState(name string) (State, error) {
	out, err := exec.Command("lswpar", "-c", "-q", "-a", "name,state", name).Output()
	if err != nil {
		return StateUnknown, fmt.Errorf("lswpar -c -q -a name,state %s: %w", name, err)
	}
	// Expected output: "name:state\n"
	line := strings.TrimSpace(string(out))
	if line == "" {
		return StateUnknown, fmt.Errorf("wpar %q not found (empty lswpar output)", name)
	}
	// There may be multiple lines; use the first non-empty one.
	for _, l := range strings.Split(line, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.SplitN(l, ":", 2)
		if len(parts) < 2 {
			continue
		}
		state := strings.TrimSpace(parts[1])
		switch state {
		case "A":
			return StateActive, nil
		default:
			return StateDown, nil
		}
	}
	return StateUnknown, fmt.Errorf("wpar %q not found in lswpar output", name)
}
