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

package wpar

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	bootapi "github.com/containerd/containerd/api/runtime/bootstrap/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/log"
)

const (
	// RuntimeName is the containerd runtime identifier for the WPAR shim.
	RuntimeName = "io.containerd.wpar.v1"

	// ShimBinaryName is the name of the shim executable on PATH.
	ShimBinaryName = "containerd-shim-wpar-v1"
)

// Manager implements shim.Shim for the AIX WPAR runtime.
// It is responsible for spawning and stopping the per-task shim process.
type Manager struct{}

// NewManager returns a new WPAR shim manager.
func NewManager(name string) shim.Shim {
	return &Manager{}
}

// Name returns the runtime name.
func (m *Manager) Name() string { return RuntimeName }

// Info returns metadata about this runtime.
func (m *Manager) Info(ctx context.Context, optionsR io.Reader) (*types.RuntimeInfo, error) {
	return &types.RuntimeInfo{
		Name: RuntimeName,
		Version: &types.RuntimeVersion{
			Version: "v1.0.0",
		},
	}, nil
}

// Start spawns a new long-running shim server process for the given task.
//
// Unlike the previous implementation, we do NOT re-exec with "start" as an
// action argument — that caused a fork bomb because Manager.Start was called
// from within the process that was *already* handling "start". Instead we:
//
//  1. Create the ttrpc socket and obtain its file descriptor.
//  2. Spawn the same binary with NO action argument (server mode), passing the
//     socket fd as an inherited extra file.
//  3. Return the socket address to containerd without closing the listener here
//     (the child inherits the fd; we close our copy after Start).
func (m *Manager) Start(ctx context.Context, params *bootapi.BootstrapParams) (*bootapi.BootstrapResult, error) {
	shimBin, err := exec.LookPath(ShimBinaryName)
	if err != nil {
		return nil, fmt.Errorf("shim binary %q not found in PATH: %w", ShimBinaryName, err)
	}

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	socketDir := params.GetSocketDir()
	if socketDir == "" {
		socketDir = defaults.DefaultStateDir + "/s"
	}

	// Compute the socket address (same formula used by pkg/shim).
	address, err := shim.CreateSocketAddress(ctx, socketDir,
		params.GetContainerdGrpcAddress(), params.GetInstanceID(), false)
	if err != nil {
		return nil, fmt.Errorf("create socket address: %w", err)
	}

	// If a socket already exists and is accepting connections, reuse it.
	if shim.CanConnect(address) {
		return &bootapi.BootstrapResult{
			Version:  3,
			Protocol: "ttrpc",
			Address:  address,
		}, nil
	}

	// Remove any stale socket file.
	_ = shim.RemoveSocket(address)

	socket, err := shim.NewSocket(address)
	if err != nil {
		return nil, fmt.Errorf("create shim socket %s: %w", address, err)
	}

	// Obtain the underlying *os.File for the listener so we can pass it to
	// the child as an inherited fd. We MUST NOT close the listener before
	// cmd.Start() — if we do the file descriptor is closed and the child
	// inherits a closed fd.
	socketFile, err := socket.File()
	if err != nil {
		socket.Close()
		_ = shim.RemoveSocket(address)
		return nil, fmt.Errorf("get socket file: %w", err)
	}

	// Build the long-running server command. No action argument — the shim
	// binary detects that it was started without "start"/"delete" and enters
	// server mode, reading the ttrpc socket from ExtraFiles[0] (fd 3).
	id := params.GetInstanceID()
	cmd := exec.Command(shimBin,
		"-namespace", ns,
		"-id", id,
		"-address", params.GetContainerdGrpcAddress(),
	)
	cmd.Dir = "/" // Never use the bundle dir (issue 16)
	cmd.Stdout = nil
	// Do NOT inherit the start process's stderr. containerd reads everything the
	// "start" binary prints on stdout+stderr as the bootstrap result
	// (core/runtime/v2/binary.go CombinedOutput), so any shim server output
	// before it detaches would corrupt the address string containerd tries to
	// dial. Redirect to a log file instead.
	shimLogPath := socketDir + "/" + id + "-shim.log"
	shimLog, err := os.OpenFile(shimLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		// Fall back to /dev/null rather than inheriting start-process stderr.
		shimLog, _ = os.Open(os.DevNull)
	}
	cmd.Stderr = shimLog
	cmd.ExtraFiles = []*os.File{socketFile}
	// Start a new session so the server survives the start process exiting.
	setSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		socketFile.Close()
		shimLog.Close()
		socket.Close()
		_ = shim.RemoveSocket(address)
		return nil, fmt.Errorf("spawn shim server: %w", err)
	}

	// Close our copies — the child has its own inherited fds.
	socketFile.Close()
	shimLog.Close()
	socket.Close()

	// Detach the child wait; we do not track the server PID in the manager.
	go cmd.Wait() //nolint:errcheck

	// Give the server a moment to start accepting connections.
	if err := waitForSocket(address, 3*time.Second); err != nil {
		log.G(ctx).WithError(err).Warn("wpar: shim server did not become ready quickly; continuing")
	}

	return &bootapi.BootstrapResult{
		Version:  3,
		Protocol: "ttrpc",
		Address:  address,
	}, nil
}

// Stop cleans up after a shim by running stopwpar+rmwpar directly.
//
// We do NOT re-exec the shim binary with "delete" — that caused the same
// fork-bomb pattern as Start. Instead we run the WPAR teardown commands
// directly from cwd "/" so they survive bundle directory deletion (issue 16).
func (m *Manager) Stop(ctx context.Context, id string) (shim.StopStatus, error) {
	name := wparName(id)

	// Run all WPAR teardown from "/" to avoid inheriting a deleted cwd.
	// rmwpar -F stops and destroys the WPAR in one step. If the WPAR is
	// already gone that is fine — ignore NotFound-style errors.
	if err := runCmdDetached(ctx, "rmwpar", "-F", name); err != nil {
		log.G(ctx).WithError(err).Warn("wpar: rmwpar during Stop; WPAR may already be gone")
	}

	return shim.StopStatus{ExitedAt: time.Now()}, nil
}

// waitForSocket polls the socket address until it accepts connections or the
// deadline is reached.
func waitForSocket(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath(address), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("shim socket not ready within timeout: %s", address)
}

// socketPath strips the "unix://" prefix from a socket address.
func socketPath(address string) string {
	const prefix = "unix://"
	if len(address) > len(prefix) && address[:len(prefix)] == prefix {
		return address[len(prefix):]
	}
	return address
}

// runCmdDetached runs an external command from cwd "/" so it is not tied to
// the bundle directory (which containerd may delete during teardown). The
// context is detached to a background context with a generous timeout so the
// command is not killed when the request context is cancelled (issue 15).
func runCmdDetached(ctx context.Context, name string, args ...string) error {
	bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	log.G(ctx).WithField("cmd", append([]string{name}, args...)).Debug("wpar: running teardown command")
	cmd := exec.CommandContext(bgCtx, name, args...)
	cmd.Dir = "/"
	setSysProcAttr(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, string(out))
	}
	return nil
}
