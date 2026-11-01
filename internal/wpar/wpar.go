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
//	mkwpar    – create a new WPAR
//	startwpar – start a previously created WPAR
//	stopwpar  – stop a running WPAR
//	rmwpar    – destroy a WPAR
//	lswpar    – query WPAR state
//
// Process execution inside WPARs uses clogin(1).
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
	"syscall"
	"time"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/shim"
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
	// Wpool is the log=NULL copy directory (/wpool/NAME) used by fast-clone.
	Wpool string `json:"wpool,omitempty"`
}

// WPAR represents a single managed AIX Workload Partition.
type WPAR struct {
	mu sync.Mutex

	// cmdMu serialises WPAR management commands (stopwpar, rmwpar).
	// Kill acquires it for the duration of stopwpar; Delete acquires it
	// before starting rmwpar -F.  waitForProcess waits for cmdMu to drain
	// (by acquiring+releasing) before publishing TaskExit, so containerd
	// cannot call Delete until any in-flight stopwpar has returned.
	cmdMu sync.Mutex

	id         string // containerd task ID
	name       string // AIX WPAR name (max 25 chars, derived from id)
	bundlePath string
	rootdir    string
	// wpool is the log=NULL copy directory used by the fast-clone path
	// (/wpool/NAME).  Empty on the slow path.
	wpool string

	pid      uint32
	state    State
	exitCode uint32
	exitedAt time.Time

	waiters []chan struct{} // closed when the WPAR transitions to StateDown

	// Security subsystems — populated during the ordered startup sequence.
	// All fields are set before the container process is released.

	// policy is the unified security policy record for this container.
	policy *SecurityPolicy

	// wlm manages WLM CPU/memory/process controls.
	wlm *WLMController

	// kmod manages the per-WPAR syscall bitmap policy.
	kmod *KmodPolicyManager

	// procMon is the global /proc monitoring daemon (shared across WPARs).
	procMon *ProcMonitor

	// fsConfig holds the filesystem isolation configuration used during
	// Setup and Teardown.
	fsConfig *FSIsolationConfig

	// hostname is the Kubernetes pod hostname assigned to this WPAR.
	hostname string

	// stdoutFIFO and stderrFIFO are the containerd FIFO paths stored at
	// Create time (from CreateTaskRequest.Stdout/Stderr) and consumed at Start.
	stdoutFIFO string
	stderrFIFO string
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
		wpool:      sf.Wpool,
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

// WithSecurityPolicy attaches the unified security policy to the WPAR.
// Must be called before the ordered startup sequence begins.
func (w *WPAR) WithSecurityPolicy(p *SecurityPolicy) *WPAR {
	w.mu.Lock()
	w.policy = p
	w.mu.Unlock()
	return w
}

// SecurityPolicy returns the container's security policy (may be nil before
// the startup sequence sets it).
func (w *WPAR) SecurityPolicy() *SecurityPolicy {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.policy
}

// WithWLM attaches the WLM resource controller.
func (w *WPAR) WithWLM(c *WLMController) *WPAR {
	w.mu.Lock()
	w.wlm = c
	w.mu.Unlock()
	return w
}

// WithKmod attaches the kmod policy manager.
func (w *WPAR) WithKmod(k *KmodPolicyManager) *WPAR {
	w.mu.Lock()
	w.kmod = k
	w.mu.Unlock()
	return w
}

// WithProcMon attaches the global /proc monitor.
func (w *WPAR) WithProcMon(m *ProcMonitor) *WPAR {
	w.mu.Lock()
	w.procMon = m
	w.mu.Unlock()
	return w
}

// WithFSConfig attaches the filesystem isolation configuration.
func (w *WPAR) WithFSConfig(cfg *FSIsolationConfig) *WPAR {
	w.mu.Lock()
	w.fsConfig = cfg
	w.mu.Unlock()
	return w
}

// WithHostname sets the Kubernetes pod hostname for this WPAR.
func (w *WPAR) WithHostname(h string) *WPAR {
	w.mu.Lock()
	w.hostname = h
	w.mu.Unlock()
	return w
}

// IsOOMKilled returns true when the WLM memory monitor terminated this
// workload due to its configured memory limit.
func (w *WPAR) IsOOMKilled() bool {
	w.mu.Lock()
	wlm := w.wlm
	w.mu.Unlock()
	if wlm == nil {
		return false
	}
	return wlm.IsOOMKilled()
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
		Wpool:    w.wpool,
	}
	w.mu.Unlock()

	data, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(w.bundlePath), data, 0600)
}

// wparTemplateDir is the sentinel directory whose existence triggers the
// fast-clone path.  The template itself lives here.
const wparTemplateDir = "/wpars/.template"

// wpoolBase is the log=NULL file system used by the fast-clone path.
// Copies go into /wpool/NAME; this is mounted on its own file system so the
// pax copy runs at disk speed (~1 s) rather than through the journal (~2 min).
// rmwpar leaves /wpool/NAME behind; Delete removes it.
const wpoolBase = "/wpool"

// Create allocates the WPAR via mkwpar.
//
// Fast path (mkwpar -p): if a pre-built template directory exists at
// wparTemplateDir, we copy it into the per-WPAR directory and then call
// "mkwpar -n NAME -p NAME" which attaches the existing /etc/filesystems
// stanzas and skips the costly populate step (~1 s vs ~8 min).
//
// Slow path (fallback): if no template exists, we fall back to the
// traditional "mkwpar -n NAME -d BASEDIR -M directory=/ -M vfs=directory"
// invocation followed by a pax rootfs copy.  This path works on a fresh box
// but takes ~8 minutes per WPAR.
//
// mkwpar constraints (both paths):
//   - The -d base directory must be empty; mkwpar creates it itself.
//   - The parent of -d must exist with mode 0700.
//   - WPAR names are at most 25 bytes and must not start with a digit.
//   - Do NOT pass -N (that is the network flag, not "don't start").
//   - mkwpar does not start the WPAR unless given -s.
//   - -M flags must be separate words: "-M" "directory=/" "-M" "vfs=directory"
//     (not a single "-M" "directory=/ vfs=directory" argument).
func (w *WPAR) Create(ctx context.Context) error {
	w.mu.Lock()
	if w.state != StateDown {
		w.mu.Unlock()
		return fmt.Errorf("wpar %s is not in down state (state=%s)", w.name, w.state)
	}
	w.mu.Unlock()

	if _, err := os.Stat(wparTemplateDir); err == nil {
		return w.createFast(ctx)
	}
	return w.createSlow(ctx)
}

// createFast implements the mkwpar -p fast-clone path.
//
// Steps (from the validation notes performance section):
//  1. Create /wpool/NAME on the log=NULL file system (~1 s for 3,250 files).
//  2. Copy the template directory tree into /wpool/NAME.
//  3. Copy the container image rootfs on top of the template.
//  4. Write four /etc/filesystems stanzas keyed by /wpars/NAME mount points,
//     with the / stanza pointing dev at /wpool/NAME.  mkwpar -p attaches
//     the stanzas — without them it fails or picks up the template's stanzas.
//  5. Run "mkwpar -n NAME -p NAME" (~2 s).  Skips populate entirely.
//
// Teardown: rmwpar -F removes the kernel WPAR registration and its mounts
// (~0.6 s).  It leaves /wpool/NAME behind; Delete removes it.
func (w *WPAR) createFast(ctx context.Context) error {
	wpoolDir := wpoolBase + "/" + w.name

	if err := os.MkdirAll(wpoolBase, 0755); err != nil {
		return fmt.Errorf("create %s: %w", wpoolBase, err)
	}
	// pax -rw -pe requires the destination to exist.
	if err := os.MkdirAll(wpoolDir, 0755); err != nil {
		return fmt.Errorf("create wpool dir %s: %w", wpoolDir, err)
	}

	// Copy template then overlay the container image rootfs.
	if err := copyRootfs(ctx, wparTemplateDir, wpoolDir); err != nil {
		_ = os.RemoveAll(wpoolDir)
		return fmt.Errorf("copy wpar template: %w", err)
	}
	if err := copyRootfs(ctx, w.rootdir, wpoolDir); err != nil {
		_ = os.RemoveAll(wpoolDir)
		return fmt.Errorf("copy image rootfs into wpool: %w", err)
	}

	// Record wpool so Delete can clean it up even after a shim restart.
	w.mu.Lock()
	w.wpool = wpoolDir
	w.mu.Unlock()

	// Write /etc/filesystems stanzas for this WPAR before mkwpar -p.
	// The / stanza's dev points at wpoolDir (the log=NULL copy, not /wpars/NAME).
	if err := w.writeFilesystemsStanzas(wpoolDir); err != nil {
		_ = os.RemoveAll(wpoolDir)
		return fmt.Errorf("write /etc/filesystems stanzas: %w", err)
	}

	// mkwpar -n NAME -p NAME: attach the stanzas we just wrote.
	if err := runCmdAt(ctx, "/", "mkwpar", "-n", w.name, "-p", w.name); err != nil {
		_ = w.removeFilesystemsStanzas()
		_ = os.RemoveAll(wpoolDir)
		return fmt.Errorf("mkwpar -p: %w", err)
	}

	return w.saveState()
}

// writeFilesystemsStanzas appends the four required /etc/filesystems stanzas
// for the new WPAR to the host's /etc/filesystems file.
//
// The stanzas mirror the layout written by a normal mkwpar:
//   - /     namefs (rw) over baseDir (the /wpool/NAME copy on fast path)
//   - /usr  namefs (ro) from the host
//   - /opt  namefs (ro) from the host
//   - /proc namefs (rw) over /proc  — NOT procfs; mkwpar writes namefs here
//
// mkwpar -p skips all file system creation and the costly populate step; it
// only calls into the kernel to register the WPAR against the stanzas it
// finds in /etc/filesystems. Without this step, -p either fails or attaches
// the template's stanzas (which point to the wrong directory).
func (w *WPAR) writeFilesystemsStanzas(baseDir string) error {
	// Stanza names are full mount-point paths so mkwpar -p and rmwpar find them.
	// type = WPAR name so rmwpar recognises and removes them on delete.
	// mount = true would mean "mount at boot from global env" — omit it.
	mp := "/wpars/" + w.name
	stanzas := mp + ":\n" +
		"\tdev\t\t= " + baseDir + "\n" +
		"\tvfs\t\t= namefs\n" +
		"\ttype\t\t= " + w.name + "\n" +
		"\n" +
		mp + "/usr:\n" +
		"\tdev\t\t= /usr\n" +
		"\tvfs\t\t= namefs\n" +
		"\ttype\t\t= " + w.name + "\n" +
		"\toptions\t\t= ro\n" +
		"\n" +
		mp + "/opt:\n" +
		"\tdev\t\t= /opt\n" +
		"\tvfs\t\t= namefs\n" +
		"\ttype\t\t= " + w.name + "\n" +
		"\toptions\t\t= ro\n" +
		"\n" +
		mp + "/proc:\n" +
		"\tdev\t\t= /proc\n" +
		"\tvfs\t\t= namefs\n" +
		"\ttype\t\t= " + w.name + "\n" +
		"\toptions\t\t= rw\n" +
		"\n"

	return writeFilesystemsAtomic(stanzas)
}

// removeFilesystemsStanzas removes the stanzas added by writeFilesystemsStanzas.
// Called on rollback when mkwpar -p fails.
// Stanza names are full mount-point paths (/wpars/NAME, /wpars/NAME/usr, …).
func (w *WPAR) removeFilesystemsStanzas() error {
	prefix := "/wpars/" + w.name
	return rewriteFilesystemsAtomic(func(line string) bool {
		// A stanza header for this WPAR starts with the full mount-point path
		// followed by ':'.  Skip the header and all indented attribute lines.
		return strings.HasPrefix(line, prefix+":") ||
			strings.HasPrefix(line, prefix+"/")
	})
}

// splitLines splits s into lines without trailing newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

const etcFilesystems = "/etc/filesystems"

// writeFilesystemsAtomic appends stanzas to /etc/filesystems under a POSIX
// advisory lock (fcntl F_SETLKW), then rewrites atomically via a temp file +
// rename.  The lock is held on /etc/filesystems.lck (a file that is never
// deleted so the lock descriptor survives shim restarts).  The kernel releases
// it automatically when the process exits, so a crashed shim cannot strand it.
//
// Note: mkwpar/rmwpar/crfs/chfs do NOT use this lock.  A concurrent AIX tool
// write can still race, though this is less likely than shim-against-shim.
func writeFilesystemsAtomic(stanzas string) error {
	return modifyFilesystemsAtomic(func(data []byte) ([]byte, error) {
		// Trim trailing blank lines, then append one blank separator before
		// the new stanzas.  This prevents blank lines from accumulating across
		// multiple Create calls.
		trimmed := strings.TrimRight(string(data), "\n")
		return []byte(trimmed + "\n\n" + stanzas), nil
	})
}

// rewriteFilesystemsAtomic removes all stanzas whose header line satisfies
// isHeader from /etc/filesystems, under a lock.  A stanza consists of its
// header line and any immediately following whitespace-indented lines
// (tab or space, to cope with tools that rewrite with spaces).
func rewriteFilesystemsAtomic(isHeader func(string) bool) error {
	return modifyFilesystemsAtomic(func(data []byte) ([]byte, error) {
		var out []byte
		skip := false
		for _, line := range splitLines(string(data)) {
			if len(line) > 0 && line[0] != '\t' && line[0] != ' ' {
				// Non-indented line: a stanza header (or blank separator).
				skip = isHeader(line)
			}
			if !skip {
				out = append(out, []byte(line+"\n")...)
			}
		}
		return out, nil
	})
}

// modifyFilesystemsAtomic acquires a POSIX write lock on etcFilesystems+".lck"
// (created once, never deleted), reads etcFilesystems, calls fn, and writes
// the result back via an atomic rename.  The lock is released when the
// returned file descriptor is closed (or the process exits).
func modifyFilesystemsAtomic(fn func([]byte) ([]byte, error)) error {
	const lockPath = etcFilesystems + ".lck"

	// Open (or create) the companion lock file.  We never delete it so that
	// processes that already hold an fd to it don't lose their lock.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open /etc/filesystems lock file: %w", err)
	}
	defer lf.Close()

	// F_SETLKW: blocking exclusive write lock; kernel releases on process exit.
	lk := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: int16(0), // SEEK_SET
		Start:  0,
		Len:    0, // entire file
	}
	if err := unix.FcntlFlock(lf.Fd(), unix.F_SETLKW, &lk); err != nil {
		return fmt.Errorf("lock /etc/filesystems: %w", err)
	}

	data, err := os.ReadFile(etcFilesystems)
	if err != nil {
		return fmt.Errorf("read %s: %w", etcFilesystems, err)
	}

	newData, err := fn(data)
	if err != nil {
		return err
	}

	// Preserve the original mode (AIX ships /etc/filesystems as 0664).
	fi, err := os.Stat(etcFilesystems)
	mode := os.FileMode(0664)
	if err == nil {
		mode = fi.Mode().Perm()
	}

	tmp := etcFilesystems + ".tmp"
	if err := os.WriteFile(tmp, newData, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, etcFilesystems); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, etcFilesystems, err)
	}
	return nil
}

// createSlow implements the traditional mkwpar path (no pre-built template).
func (w *WPAR) createSlow(ctx context.Context) error {
	// mkwpar creates the base directory itself; the parent must be mode 0700.
	baseDir := "/wpars/" + w.name
	if err := os.MkdirAll("/wpars", 0700); err != nil {
		return fmt.Errorf("create /wpars: %w", err)
	}

	// One -M flag with two separate attribute words: directory=/ vfs=directory.
	// (Two separate -M flags each with one attribute is also rejected by mkwpar.)
	args := []string{"-n", w.name, "-d", baseDir, "-M", "directory=/", "vfs=directory"}
	if err := runCmdAt(ctx, "/", "mkwpar", args...); err != nil {
		return fmt.Errorf("mkwpar: %w", err)
	}

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
func (w *WPAR) Start(ctx context.Context, specArgs []string, specEnv []string, specCwd string, stdoutFIFO, stderrFIFO string, publisher shim.Publisher, pubCtx context.Context) error {
	if err := runCmdAt(ctx, "/", "startwpar", w.name); err != nil {
		return fmt.Errorf("startwpar: %w", err)
	}

	w.mu.Lock()
	w.state = StateActive
	w.mu.Unlock()

	if err := w.saveState(); err != nil {
		return err
	}

	// Run the container process inside the WPAR via clogin(1).
	// clogin joins its arguments into a single shell command, so every
	// argument must be shell-quoted.
	pid, err := w.runProcess(ctx, specArgs, specEnv, specCwd, stdoutFIFO, stderrFIFO, publisher, pubCtx)
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
//   - "clogin NAME CMD" — NOT "clogin -R NAME CMD" (-R is for WPAR name, but
//     the correct form without flags is simply "clogin NAME CMD").
//   - clogin joins all arguments into one string and passes it to a shell.
//     Every argument must be shell-quoted.
//   - The process must NOT be started with exec.CommandContext because ttrpc
//     cancels the request context as soon as the Start handler returns, which
//     would deliver SIGKILL to clogin immediately.  Use exec.Command instead
//     and manage the lifetime explicitly.
//   - stdin does not pass through (the program inside gets EBADF). We connect
//     /dev/null.
//   - We wire stdout and stderr to containerd's FIFOs.
//   - clogin passes the exit code through; for signal death we report 128+sig.
func (w *WPAR) runProcess(_ context.Context, args []string, env []string, cwd string, stdoutFIFO, stderrFIFO string, publisher shim.Publisher, pubCtx context.Context) (uint32, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("runProcess: no command specified")
	}

	// Build: cd '<cwd>' && exec /usr/bin/env -i 'K=V'... 'arg0' 'arg1'...
	// env -i keeps the shim's own environment out of the container.
	var shellCmd strings.Builder
	if cwd != "" {
		shellCmd.WriteString("cd ")
		shellCmd.WriteString(shellQuote(cwd))
		shellCmd.WriteString(" && ")
	}
	shellCmd.WriteString("exec /usr/bin/env -i")
	for _, e := range env {
		shellCmd.WriteByte(' ')
		shellCmd.WriteString(shellQuote(e))
	}
	for _, a := range args {
		shellCmd.WriteByte(' ')
		shellCmd.WriteString(shellQuote(a))
	}

	// clogin NAME SHELLCMD  (no -R flag)
	// Do NOT use exec.CommandContext here: ttrpc cancels the Start handler's
	// context on return, which would immediately SIGKILL the clogin process.
	cmd := exec.Command("clogin", w.name, shellCmd.String()) //nolint:gosec
	cmd.Dir = "/"
	cmd.Stdin = nil // /dev/null inherited from the process

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

	// Wait for clogin in the background; close the WPAR waiters when done
	// and publish the TaskExit event so ctr/CRI learns the container exited.
	go w.waitForProcess(cmd, publisher, pubCtx)

	return pid, nil
}

// waitForProcess waits for the clogin process to exit, records the exit code,
// notifies all waiters, and publishes the TaskExit event.
func (w *WPAR) waitForProcess(cmd *exec.Cmd, publisher shim.Publisher, pubCtx context.Context) {
	err := cmd.Wait()

	var exitCode uint32
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Use syscall.WaitStatus.Signaled() to detect signal death.
			// exitErr.Sys().(interface{ Signal() int }) never matches on AIX
			// because syscall.WaitStatus.Signal() returns syscall.Signal, not int.
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				exitCode = uint32(128 + ws.Signal())
			} else {
				exitCode = uint32(exitErr.ExitCode())
			}
		}
	}

	now := time.Now()
	w.mu.Lock()
	w.state = StateDown
	w.exitCode = exitCode
	if w.exitedAt.IsZero() {
		w.exitedAt = now
	}
	exitedAt := w.exitedAt
	pid := w.pid
	id := w.id
	waiters := w.waiters
	w.waiters = nil
	w.mu.Unlock()

	_ = w.saveState()

	// Wait for any in-flight Kill (stopwpar) to finish before publishing
	// TaskExit.  Without this, containerd receives TaskExit while stopwpar is
	// still running, calls Delete immediately, and Delete's rmwpar -F collides
	// with the in-flight stopwpar ("wparlockctl failed, rc 2").
	// cmdMu is held by Kill for the duration of stopwpar; acquiring it here
	// guarantees stopwpar has returned before TaskExit is published.
	w.cmdMu.Lock()
	w.cmdMu.Unlock() //nolint:staticcheck // intentional drain

	// Publish the TaskExit event. Without this, ctr run never returns and
	// CRI never learns that the container exited.
	if publisher != nil {
		_ = publisher.Publish(pubCtx, runtime.TaskExitEventTopic, &eventstypes.TaskExit{
			ContainerID: id,
			ID:          id,
			Pid:         pid,
			ExitStatus:  exitCode,
			ExitedAt:    timestamppb.New(exitedAt),
		})
	}

	for _, ch := range waiters {
		close(ch)
	}
}

// releaseWaiters unblocks any goroutines blocked in Wait(). It is called
// during Delete for tasks that were never started (state never reached
// StateActive, so waitForProcess never ran).
func (w *WPAR) releaseWaiters() {
	w.mu.Lock()
	waiters := w.waiters
	w.waiters = nil
	w.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
}

// shellQuote returns a safely shell-quoted version of s using single quotes.
func shellQuote(s string) string {
	// Replace every ' with '\'' to handle single quotes inside the string.
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Kill sends a signal to the WPAR.
//
// SIGKILL → stopwpar -F (immediate force-stop; equivalent to sending SIGKILL
// to every process in the partition).
// SIGTERM → stopwpar (graceful stop; sends SIGTERM to the WPAR's init process
// and waits up to 90 s by default).
// Other signals are delivered to the clogin process directly. This works for
// signals that the container's process traps (e.g. SIGHUP, SIGUSR1/2), because
// clogin is the direct parent and is in the global root. For SIGINT this
// kills the clogin process rather than routing INT into the WPAR; a
// full fix requires finding the container's PID under clogin.
//
// cmdMu serialises WPAR management commands so that a concurrent Delete cannot
// start rmwpar -F while stopwpar is still running (which causes "wparlockctl
// failed, rc 2").  waitForProcess waits for cmdMu before publishing TaskExit,
// ensuring containerd cannot call Delete until stopwpar has returned.
func (w *WPAR) Kill(ctx context.Context, signal uint32, all bool) error {
	w.mu.Lock()
	state := w.state
	name := w.name
	w.mu.Unlock()

	if state != StateActive {
		return errdefs.ErrNotFound
	}

	const sigkill = 9
	const sigterm = 15

	switch signal {
	case sigkill:
		// Force-stop: stopwpar -F does an immediate SIGKILL to all processes.
		w.cmdMu.Lock()
		err := runCmdAt(ctx, "/", "stopwpar", "-F", name)
		w.cmdMu.Unlock()
		if err != nil {
			return fmt.Errorf("stopwpar -F: %w", err)
		}
		return nil
	case sigterm:
		// Graceful stop.
		w.cmdMu.Lock()
		err := runCmdAt(ctx, "/", "stopwpar", name)
		w.cmdMu.Unlock()
		if err != nil {
			return fmt.Errorf("stopwpar: %w", err)
		}
		return nil
	default:
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

// Delete destroys the WPAR asynchronously and removes the persisted state file.
//
// rmwpar -F is run in a detached background goroutine so Delete returns before
// CRI's 10 s RPC deadline.  It acquires cmdMu before starting rmwpar so it
// cannot collide with an in-flight stopwpar from Kill.
//
// The base directory (/wpars/NAME) and the wpool copy (/wpool/NAME) are only
// removed once lswpar confirms the WPAR no longer exists.  "No longer exists"
// means lswpar returns an error (WPAR not found) — every state code including
// Broken (B) and transitional (T) means it still occupies the directory tree.
func (w *WPAR) Delete(ctx context.Context) error {
	w.mu.Lock()
	name := w.name
	baseDir := "/wpars/" + w.name
	wpoolDir := w.wpool
	statFile := statePath(w.bundlePath)
	w.mu.Unlock()

	// Remove the state file immediately so the shim does not try to reload a
	// partially deleted WPAR on restart.
	_ = os.Remove(statFile)

	// Release any waiters blocked in Wait() so they don't leak goroutines.
	w.releaseWaiters()

	// Run rmwpar -F in the background.  We hold cmdMu for the duration so
	// Kill (stopwpar) cannot run concurrently.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		w.cmdMu.Lock()
		err := runCmdAt(bgCtx, "/", "rmwpar", "-F", name)
		w.cmdMu.Unlock()
		if err != nil {
			log.G(bgCtx).WithError(err).Warn("wpar: rmwpar -F failed; WPAR may already be gone")
		}

		// Only remove directories once lswpar confirms the WPAR is gone.
		// An lswpar error (not found) is the success case.  Any listed state
		// (A, B, T, D …) means the WPAR still exists and still owns the tree.
		if _, err := lswparState(name); err == nil {
			log.G(bgCtx).Warn("wpar: WPAR still registered after rmwpar -F; skipping directory removal")
			return
		}

		// Confirm nothing is still mounted under baseDir before removing it.
		if hasMounts, merr := pathHasMounts(baseDir); merr != nil || hasMounts {
			if merr != nil {
				log.G(bgCtx).WithError(merr).Warn("wpar: mountinfo check failed; skipping base dir removal")
			} else {
				log.G(bgCtx).Warn("wpar: mounts still present under base dir; skipping removal")
			}
		} else {
			_ = os.RemoveAll(baseDir)
		}

		// Remove the wpool copy (fast-clone path only).
		if wpoolDir != "" {
			_ = os.RemoveAll(wpoolDir)
		}
	}()

	return nil
}

// pathHasMounts reports whether any mount point in the system mount table is
// rooted under path (i.e. path is a prefix of the mount point).
func pathHasMounts(path string) (bool, error) {
	entries, err := mountinfo.GetMounts(nil)
	if err != nil {
		return false, err
	}
	prefix := strings.TrimRight(path, "/") + "/"
	for _, e := range entries {
		mp := strings.TrimRight(e.Mountpoint, "/") + "/"
		if strings.HasPrefix(mp, prefix) || e.Mountpoint == path {
			return true, nil
		}
	}
	return false, nil
}

// Wait returns a channel that is closed when the WPAR transitions to StateDown.
func (w *WPAR) Wait() <-chan struct{} {
	ch := make(chan struct{})
	w.mu.Lock()
	// Block until exitedAt is set, not just StateDown.
	// A newly created task is StateDown but has no exit yet; closing the channel
	// immediately would cause ctr/CRI to see an instant "exited 0" before the
	// container has run. waitForProcess sets exitedAt before closing waiters.
	if !w.exitedAt.IsZero() {
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
