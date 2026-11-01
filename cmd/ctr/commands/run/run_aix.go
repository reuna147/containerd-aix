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

// AIX-specific implementation of the ctr run sub-command.
//
// Linux-only features that are absent here:
//   - CDI / GPU device injection (tags.cncf.io/container-device-interface)
//   - blockio / Intel RDT (github.com/intel/goresctrl)
//   - seccomp (Linux kernel feature)
//   - AppArmor (Linux kernel feature)
//   - User namespace ID mappings --uidmap / --gidmap (no AIX kernel support)
//   - --with-ns Linux namespace joining (WPAR runtime does not support it)
//   - --remap-labels (depends on user namespaces)
//   - Advanced cgroup resource flags: --cpus, --cpu-shares, --cpuset-cpus,
//     --cpuset-mems, --cpu-quota, --cpu-period, --cpu-burst, --memory-limit
//     (no cgroup enforcement; WPAR uses AIX resource management instead)
//   - --rootfs-propagation (Linux mount propagation concept)
//   - CNI network namespace path via /proc/<pid>/ns/net (AIX has no procfs netns)
//
// Features retained from the Linux implementation:
//   - Container creation from an OCI image or a pre-existing rootfs
//   - Snapshotter / snapshotter-labels
//   - env / env-file
//   - Mounts (--mount)
//   - TTY allocation
//   - User + additional GIDs
//   - Working directory (--cwd)
//   - Process args override
//   - Privileged mode (--privileged, --privileged-without-host-devices)
//   - Host devices (via oci.WithHostDevices)
//   - net-host (host networking)
//   - Hostname
//   - Labels + annotations
//   - Read-only rootfs
//   - Sandbox
//   - RLIMIT_NOFILE
//   - Linux capabilities add/drop (spec fields; enforcement is WPAR-runtime dependent)
//
// This file is intentionally kept minimal so that later stages (e.g. Buildah-produced
// AIX images consumed via the WPAR runtime) do not inherit Linux-only assumptions.

package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/platforms"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/cmd/ctr/commands"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/oci"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli/v3"
)

// platformRunFlags are the AIX-specific flags added to the run command.
// Linux-only flags (CDI, blockio, RDT, uidmap, gidmap, remap-labels,
// cpus/cpu-shares/cpuset-*, cpu-quota/period/burst, memory-limit,
// rootfs-propagation) are intentionally omitted.
var platformRunFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "rlimit-nofile",
		Usage: "Set RLIMIT_NOFILE (soft:hard)",
	},
}

// NewContainer creates a new container for the AIX WPAR runtime.
// It mirrors the structure of run_unix.go (Linux) but omits all Linux-only
// features so that the WPAR shim can consume the resulting OCI bundle cleanly.
func NewContainer(ctx context.Context, client *containerd.Client, cmd *cli.Command) (containerd.Container, error) {
	var (
		id     string
		config = cmd.IsSet("config")
	)
	if config {
		id = cmd.Args().First()
	} else {
		id = cmd.Args().Get(1)
	}

	// Determine the target platform. For AIX the default is aix/ppc64.
	// The user may override with --platform to pull a cross-platform image config.
	platform := cmd.String("platform")
	if platform == "" {
		plat := platforms.DefaultSpec()
		platform = platforms.FormatAll(plat)
	}

	var (
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
		spec  containerd.NewContainerOpts
	)

	if sandbox := cmd.String("sandbox"); sandbox != "" {
		cOpts = append(cOpts, containerd.WithSandbox(sandbox))
	}

	if config {
		cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(cmd.StringSlice("label"))))
		opts = append(opts, oci.WithSpecFromFile(cmd.String("config")))
	} else {
		var (
			ref  = cmd.Args().First()
			args = cmd.Args().Slice()[2:]
		)

		opts = append(opts, oci.WithDefaultSpecForPlatform(platform), oci.WithDefaultUnixDevices)
		if ef := cmd.String("env-file"); ef != "" {
			opts = append(opts, oci.WithEnvFile(ef))
		}
		opts = append(opts, oci.WithEnv(cmd.StringSlice("env")))
		opts = append(opts, withMounts(cmd))

		if cmd.Bool("rootfs") {
			rootfs, err := filepath.Abs(ref)
			if err != nil {
				return nil, err
			}
			opts = append(opts, oci.WithRootFSPath(rootfs))
			cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(cmd.StringSlice("label"))))
		} else {
			snapshotter := cmd.String("snapshotter")
			var image containerd.Image
			i, err := client.ImageService().Get(ctx, ref)
			if err != nil {
				return nil, err
			}
			if ps := cmd.String("platform"); ps != "" {
				p, err := platforms.Parse(ps)
				if err != nil {
					return nil, err
				}
				image = containerd.NewImageWithPlatform(client, i, platforms.Only(p))
			} else {
				image = containerd.NewImage(client, i)
			}

			unpacked, err := image.IsUnpacked(ctx, snapshotter)
			if err != nil {
				return nil, err
			}
			if !unpacked {
				if err := image.Unpack(ctx, snapshotter, containerd.WithUnpackApplyOpts(diff.WithSyncFs(cmd.Bool("sync-fs")))); err != nil {
					return nil, err
				}
			}
			labels := buildLabels(commands.LabelArgs(cmd.StringSlice("label")), image.Labels())
			opts = append(opts, oci.WithImageConfig(image))
			cOpts = append(cOpts,
				containerd.WithImage(image),
				containerd.WithImageConfigLabels(image),
				containerd.WithAdditionalContainerLabels(labels),
				containerd.WithSnapshotter(snapshotter),
				containerd.WithNewSnapshot(id, image,
					snapshots.WithLabels(commands.LabelArgs(cmd.StringSlice("snapshotter-label")))),
			)
			cOpts = append(cOpts, containerd.WithImageStopSignal(image, "SIGTERM"))
		}

		if cmd.Bool("read-only") {
			opts = append(opts, oci.WithRootFSReadonly())
		}
		if len(args) > 0 {
			opts = append(opts, oci.WithProcessArgs(args...))
		}
		if cwd := cmd.String("cwd"); cwd != "" {
			opts = append(opts, oci.WithProcessCwd(cwd))
		}
		if user := cmd.String("user"); user != "" {
			opts = append(opts, oci.WithUser(user), oci.WithAdditionalGIDs(user))
		}
		if cmd.Bool("tty") {
			opts = append(opts, oci.WithTTY)
		}

		if privileged := cmd.Bool("privileged"); privileged {
			if cmd.Bool("privileged-without-host-devices") {
				opts = append(opts, oci.WithPrivileged)
			} else {
				opts = append(opts, oci.WithPrivileged, oci.WithAllDevicesAllowed, oci.WithHostDevices)
			}
		}

		if cmd.Bool("net-host") {
			hostname, err := os.Hostname()
			if err != nil {
				return nil, fmt.Errorf("get hostname: %w", err)
			}
			opts = append(opts,
				oci.WithHostNamespace(specs.NetworkNamespace),
				oci.WithHostHostsFile,
				oci.WithHostResolvconf,
				oci.WithEnv([]string{"HOSTNAME=" + hostname}),
			)
		}

		if annoStrings := cmd.StringSlice("annotation"); len(annoStrings) > 0 {
			annos, err := commands.AnnotationArgs(annoStrings)
			if err != nil {
				return nil, err
			}
			opts = append(opts, oci.WithAnnotations(annos))
		}

		if caps := cmd.StringSlice("cap-add"); len(caps) > 0 {
			for _, c := range caps {
				if !strings.HasPrefix(c, "CAP_") {
					return nil, errors.New("capabilities must be specified with 'CAP_' prefix")
				}
			}
			opts = append(opts, oci.WithAddedCapabilities(caps))
		}

		if caps := cmd.StringSlice("cap-drop"); len(caps) > 0 {
			for _, c := range caps {
				if !strings.HasPrefix(c, "CAP_") {
					return nil, errors.New("capabilities must be specified with 'CAP_' prefix")
				}
			}
			opts = append(opts, oci.WithDroppedCapabilities(caps))
		}

		if hostname := cmd.String("hostname"); hostname != "" {
			opts = append(opts, oci.WithHostname(hostname))
		}

		if c := cmd.String("rlimit-nofile"); c != "" {
			softS, hardS, found := strings.Cut(c, ":")
			if !found {
				hardS = softS
			}
			soft, err := strconv.ParseUint(softS, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse rlimit-nofile %q: %w", c, err)
			}
			hard, err := strconv.ParseUint(hardS, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse rlimit-nofile %q: %w", c, err)
			}
			opts = append(opts, oci.WithRlimit(&specs.POSIXRlimit{
				Type: "RLIMIT_NOFILE",
				Hard: hard,
				Soft: soft,
			}))
		}
	}

	if cmd.Bool("cni") {
		cniMeta := &commands.NetworkMetaData{EnableCni: true}
		cOpts = append(cOpts, containerd.WithContainerExtension(commands.CtrCniMetadataExtension, cniMeta))
	}

	runtimeOpts, err := commands.RuntimeOptions(cmd)
	if err != nil {
		return nil, err
	}
	cOpts = append(cOpts, containerd.WithRuntime(cmd.String("runtime"), runtimeOpts))

	opts = append(opts, oci.WithAnnotations(commands.LabelArgs(cmd.StringSlice("label"))))
	var s specs.Spec
	spec = containerd.WithSpec(&s, opts...)
	cOpts = append(cOpts, spec)

	return client.NewContainer(ctx, id, cOpts...)
}

// getNetNSPath returns the network namespace path for CNI network setup.
// AIX has no /proc/<pid>/ns/net; CNI networking is not supported on AIX.
// If --cni is specified, run.go will call this function and receive an error,
// providing a clear message to the user.
func getNetNSPath(_ context.Context, _ containerd.Task) (string, error) {
	return "", errors.New("CNI networking is not supported on AIX (no /proc/<pid>/ns/net)")
}

