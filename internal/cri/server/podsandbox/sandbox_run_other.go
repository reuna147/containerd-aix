//go:build !windows && !linux

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

package podsandbox

import (
	"fmt"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/internal/cri/annotations"
	"github.com/containerd/containerd/v2/pkg/oci"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func (c *Controller) sandboxContainerSpec(id string, config *runtime.PodSandboxConfig, imageConfig *imagespec.ImageConfig, _ string, _ []string) (_ *runtimespec.Spec, _ error) {
	// The pause/sandbox image must have an entrypoint or cmd.
	if len(imageConfig.Entrypoint) == 0 && len(imageConfig.Cmd) == 0 {
		return nil, fmt.Errorf("invalid empty entrypoint and cmd in sandbox image config %+v", imageConfig)
	}

	specOpts := annotations.DefaultCRIAnnotations(id, "", c.getSandboxImageName(), config, true)

	// Apply environment variables from the image.
	if len(imageConfig.Env) > 0 {
		specOpts = append(specOpts, oci.WithEnv(imageConfig.Env))
	}

	// Apply working directory from the image.
	if imageConfig.WorkingDir != "" {
		specOpts = append(specOpts, oci.WithProcessCwd(imageConfig.WorkingDir))
	}

	specOpts = append(specOpts, oci.WithProcessArgs(append(imageConfig.Entrypoint, imageConfig.Cmd...)...))

	return c.runtimeSpec(id, specOpts...)
}

// sandboxContainerSpecOpts generates OCI spec options for
// the sandbox container. On non-Linux/non-Windows platforms the process
// args, env, and cwd are applied directly in sandboxContainerSpec; this
// function returns no additional options.
func (c *Controller) sandboxContainerSpecOpts(config *runtime.PodSandboxConfig, imageConfig *imagespec.ImageConfig) ([]oci.SpecOpts, error) {
	return nil, nil
}

// setupSandboxFiles sets up necessary sandbox files including /dev/shm, /etc/hosts,
// /etc/resolv.conf and /etc/hostname.
func (c *Controller) setupSandboxFiles(id string, config *runtime.PodSandboxConfig) error {
	return nil
}

// cleanupSandboxFiles unmount some sandbox files, we rely on the removal of sandbox root directory to
// remove these files. Unmount should *NOT* return error if the mount point is already unmounted.
func (c *Controller) cleanupSandboxFiles(id string, config *runtime.PodSandboxConfig) error {
	return nil
}

// sandboxSnapshotterOpts generates any platform specific snapshotter options
// for a sandbox container.
func sandboxSnapshotterOpts(config *runtime.PodSandboxConfig) ([]snapshots.Opt, error) {
	return []snapshots.Opt{}, nil
}
