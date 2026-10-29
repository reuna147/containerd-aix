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
	"encoding/json"
	"fmt"
	"os"
	"sync"

	shimapi "github.com/containerd/containerd/api/runtime/task/v3"
	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/log"
	"github.com/containerd/ttrpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
)

// Verify interface at compile time.
var _ shimapi.TTRPCTaskService = (*Service)(nil)

// Service implements the containerd task v3 ttrpc API backed by AIX WPARs.
type Service struct {
	mu sync.Mutex
	// wpars maps task ID → WPAR instance.
	wpars map[string]*WPAR

	publisher shim.Publisher
	sd        shutdown.Service
}

// NewService creates a new WPAR task service.
func NewService(ctx context.Context, publisher shim.Publisher, sd shutdown.Service) (*Service, error) {
	s := &Service{
		wpars:     make(map[string]*WPAR),
		publisher: publisher,
		sd:        sd,
	}
	return s, nil
}

// RegisterTTRPC registers the service on the given ttrpc server.
func (s *Service) RegisterTTRPC(server *ttrpc.Server) error {
	shimapi.RegisterTTRPCTaskService(server, s)
	return nil
}

// ---- TTRPCTaskService implementation ----------------------------------------

// Create a new WPAR-backed task.
//
// The OCI bundle (r.Bundle) must have been prepared by the snapshotter /
// bundle manager before this call. We use the bundle's "rootfs" directory as
// the WPAR root directory.
func (s *Service) Create(ctx context.Context, r *shimapi.CreateTaskRequest) (_ *shimapi.CreateTaskResponse, err error) {
	log.G(ctx).WithField("id", r.ID).WithField("bundle", r.Bundle).Debug("wpar: Create")

	rootdir := bundleRootfs(r.Bundle)
	if _, err := os.Stat(rootdir); err != nil {
		return nil, errgrpc.ToGRPC(fmt.Errorf("rootfs %s not found: %w", rootdir, errdefs.ErrNotFound))
	}

	w := NewWPAR(r.ID, r.Bundle, rootdir)

	if err := w.Create(ctx); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	s.mu.Lock()
	s.wpars[r.ID] = w
	s.mu.Unlock()

	return &shimapi.CreateTaskResponse{Pid: w.Pid()}, nil
}

// Start activates a previously created WPAR and runs the container process.
func (s *Service) Start(ctx context.Context, r *shimapi.StartRequest) (*shimapi.StartResponse, error) {
	log.G(ctx).WithField("id", r.ID).Debug("wpar: Start")

	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	// Extract the OCI spec to get the process args, env, and cwd.
	specArgs, specEnv, specCwd, stdoutFIFO, stderrFIFO, err := extractStartParams(w.bundlePath)
	if err != nil {
		return nil, errgrpc.ToGRPC(fmt.Errorf("extract spec params: %w", err))
	}

	if err := w.Start(ctx, specArgs, specEnv, specCwd, stdoutFIFO, stderrFIFO); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	return &shimapi.StartResponse{Pid: w.Pid()}, nil
}

// extractStartParams reads the OCI spec from the bundle and returns the process
// args, env, cwd, and the FIFO paths for stdout/stderr.
func extractStartParams(bundlePath string) (args []string, env []string, cwd string, stdoutFIFO, stderrFIFO string, err error) {
	specPath := bundlePath + "/config.json"
	data, readErr := os.ReadFile(specPath)
	if readErr != nil {
		return nil, nil, "", "", "", fmt.Errorf("read config.json: %w", readErr)
	}

	// Minimal struct to decode the parts of the OCI spec we need.
	var spec struct {
		Process struct {
			Args []string `json:"args"`
			Env  []string `json:"env"`
			Cwd  string   `json:"cwd"`
		} `json:"process"`
	}
	if jsonErr := json.Unmarshal(data, &spec); jsonErr != nil {
		return nil, nil, "", "", "", fmt.Errorf("parse config.json: %w", jsonErr)
	}

	args = spec.Process.Args
	env = spec.Process.Env
	cwd = spec.Process.Cwd

	// FIFO paths follow the containerd convention: <bundle>/io.containerd.runtime.v2.task/<ns>/<id>/
	// For simplicity, look for files named "stdout" and "stderr" in the bundle's parent.
	// Containerd puts them at <state_dir>/<ns>/<id>/stdout etc.
	// The shim framework wires them; we read the paths from the address file.
	// For now we try the conventional paths alongside the bundle.
	parent := bundlePath
	if f := parent + "/stdout"; fileExists(f) {
		stdoutFIFO = f
	}
	if f := parent + "/stderr"; fileExists(f) {
		stderrFIFO = f
	}

	return args, env, cwd, stdoutFIFO, stderrFIFO, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Delete stops and destroys a WPAR.
func (s *Service) Delete(ctx context.Context, r *shimapi.DeleteRequest) (*shimapi.DeleteResponse, error) {
	log.G(ctx).WithField("id", r.ID).Debug("wpar: Delete")

	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	exitCode, exitedAt := w.ExitStatus()

	if err := w.Delete(ctx); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	s.mu.Lock()
	delete(s.wpars, r.ID)
	s.mu.Unlock()

	resp := &shimapi.DeleteResponse{
		Pid:        w.Pid(),
		ExitStatus: exitCode,
	}
	if !exitedAt.IsZero() {
		resp.ExitedAt = timestamppb.New(exitedAt)
	}
	return resp, nil
}

// State returns the current status of the WPAR.
func (s *Service) State(ctx context.Context, r *shimapi.StateRequest) (*shimapi.StateResponse, error) {
	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	exitCode, exitedAt := w.ExitStatus()

	resp := &shimapi.StateResponse{
		ID:         r.ID,
		Bundle:     w.bundlePath,
		Pid:        w.Pid(),
		ExitStatus: exitCode,
	}
	switch w.CurrentState() {
	case StateActive:
		resp.Status = tasktypes.Status_RUNNING
	case StateDown:
		if !exitedAt.IsZero() {
			resp.Status = tasktypes.Status_STOPPED
			resp.ExitedAt = timestamppb.New(exitedAt)
		} else {
			resp.Status = tasktypes.Status_CREATED
		}
	default:
		resp.Status = tasktypes.Status_CREATED
	}
	return resp, nil
}

// Kill signals the WPAR.
func (s *Service) Kill(ctx context.Context, r *shimapi.KillRequest) (*emptypb.Empty, error) {
	log.G(ctx).WithField("id", r.ID).WithField("signal", r.Signal).Debug("wpar: Kill")

	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	if err := w.Kill(ctx, r.Signal, r.All); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	return &emptypb.Empty{}, nil
}

// Wait blocks until the WPAR exits and returns its status.
func (s *Service) Wait(ctx context.Context, r *shimapi.WaitRequest) (*shimapi.WaitResponse, error) {
	log.G(ctx).WithField("id", r.ID).Debug("wpar: Wait")

	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	select {
	case <-ctx.Done():
		return nil, errgrpc.ToGRPC(ctx.Err())
	case <-w.Wait():
	}

	exitCode, exitedAt := w.ExitStatus()
	resp := &shimapi.WaitResponse{ExitStatus: exitCode}
	if !exitedAt.IsZero() {
		resp.ExitedAt = timestamppb.New(exitedAt)
	}
	return resp, nil
}

// Connect returns the shim and task PIDs.
func (s *Service) Connect(ctx context.Context, r *shimapi.ConnectRequest) (*shimapi.ConnectResponse, error) {
	pid := uint32(os.Getpid())
	var taskPid uint32
	if w, err := s.get(r.ID); err == nil {
		taskPid = w.Pid()
	}
	return &shimapi.ConnectResponse{
		ShimPid: pid,
		TaskPid: taskPid,
	}, nil
}

// Shutdown stops the shim process after all tasks are gone.
func (s *Service) Shutdown(ctx context.Context, r *shimapi.ShutdownRequest) (*emptypb.Empty, error) {
	log.G(ctx).Debug("wpar: Shutdown")
	s.sd.Shutdown()
	return &emptypb.Empty{}, nil
}

// Pids returns the list of PIDs inside the WPAR.
// For now we return only the known init PID.
func (s *Service) Pids(ctx context.Context, r *shimapi.PidsRequest) (*shimapi.PidsResponse, error) {
	w, err := s.get(r.ID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	pid := w.Pid()
	resp := &shimapi.PidsResponse{}
	if pid != 0 {
		resp.Processes = append(resp.Processes, &tasktypes.ProcessInfo{Pid: pid})
	}
	return resp, nil
}

// Stats returns resource statistics for the WPAR.
// Full implementation requires parsing lswpar -E output; returns not-implemented for now.
func (s *Service) Stats(ctx context.Context, r *shimapi.StatsRequest) (*shimapi.StatsResponse, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// Exec is not yet fully implemented. Returns ErrNotImplemented with proper gRPC
// error conversion so CRI can handle it gracefully.
func (s *Service) Exec(ctx context.Context, r *shimapi.ExecProcessRequest) (*emptypb.Empty, error) {
	log.G(ctx).WithField("id", r.ID).WithField("exec_id", r.ExecID).Debug("wpar: Exec not implemented")
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// Pause — WPARs do not support suspend; not implemented.
func (s *Service) Pause(ctx context.Context, r *shimapi.PauseRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// Resume — WPARs do not support suspend; not implemented.
func (s *Service) Resume(ctx context.Context, r *shimapi.ResumeRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// Checkpoint — live migration / checkpoint is not yet implemented.
func (s *Service) Checkpoint(ctx context.Context, r *shimapi.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// ResizePty — TTY resize inside a WPAR is not yet implemented.
func (s *Service) ResizePty(ctx context.Context, r *shimapi.ResizePtyRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// CloseIO — closing stdio FDs for exec processes is not yet implemented.
func (s *Service) CloseIO(ctx context.Context, r *shimapi.CloseIORequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// Update — dynamic resource updates for WPARs are not yet implemented.
func (s *Service) Update(ctx context.Context, r *shimapi.UpdateTaskRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}

// ---- helpers ----------------------------------------------------------------

func (s *Service) get(id string) (*WPAR, error) {
	s.mu.Lock()
	w, ok := s.wpars[id]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("task %q: %w", id, errdefs.ErrNotFound)
	}
	return w, nil
}

// bundleRootfs returns the path to the OCI bundle's rootfs directory.
func bundleRootfs(bundlePath string) string {
	return bundlePath + "/rootfs"
}
