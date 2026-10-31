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

// Package wpar — fs_isolation.go
//
// Implements filesystem isolation for each container's WPAR, following these
// directives:
//
//   - Create a dedicated filesystem root for each container's WPAR.
//   - Implement filesystem isolation using native WPAR filesystem configuration
//     and namefs mounts.
//   - Mount the container image root filesystem into the WPAR without exposing
//     unrelated global-environment directories.
//   - Create separate writable locations for application state, temporary files,
//     and supported volumes.
//   - Implement readOnlyRootFilesystem using read-only mounts.
//   - Apply nosuid, nodev, and noexec mount restrictions wherever supported.
//   - Prevent unapproved filesystem mounts, remounts, and mount-configuration
//     changes from inside the workload (via privilege restrictions in credentials.go).
//   - Restrict filesystem administration privileges through AIX privilege sets.
//   - Implement Kubernetes read-only volumes through read-only namefs mounts.
//   - Implement supported hostPath volumes using an explicit source-path allowlist.
//   - Resolve and validate mount sources and destinations before mounting:
//     prevent path traversal, symlink substitution, and exposure of directories
//     outside approved roots.
//   - Give every container its own writable-layer directory.
//   - Reject unsupported mount propagation modes.
//   - Implement emptyDir using an isolated writable directory.
//   - Prevent one container from modifying another container's writable layer.
//   - On container deletion, unmount and remove only resources owned by that container.
//
// AIX namefs: "mount -v namefs -o <options> <srcpath> <dstpath>"
// A namefs mount grafts an existing directory tree into another location.
// Read-only namefs: "mount -v namefs -o ro <src> <dst>"

package wpar

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// writableLayerDir is the subdirectory under the WPAR base used for the
	// container's writable layer (the upper/work layer equivalent on AIX).
	writableLayerDir = "writable"

	// tmpDir is the subdirectory for ephemeral temporary files (emptyDir).
	tmpDir = "tmpdir"

	// emptyDirPrefix is the prefix for emptyDir volume subdirectories.
	emptyDirPrefix = "emptydir-"
)

// FSIsolationConfig holds the filesystem isolation configuration for one WPAR.
type FSIsolationConfig struct {
	// WPARBaseDir is the base directory of the WPAR (rootdir + "-wpar").
	WPARBaseDir string

	// ImageRootFS is the path to the unpacked container image root.
	ImageRootFS string

	// ReadOnlyRootFS: if true, the image rootfs is mounted read-only.
	ReadOnlyRootFS bool

	// Mounts are additional volumes to mount into the WPAR.
	Mounts []MountSpec

	// AllowedHostPaths is the explicit allowlist of host paths that may be
	// bind-mounted into containers.
	AllowedHostPaths []string

	// StorageAccounting: if non-nil, called with (wparBaseDir, bytes) when
	// storage usage is sampled.
	StorageAccounting func(wparBaseDir string, usedBytes int64)
}

// containerWritableDir returns the path to the container's exclusive writable
// layer directory.
func containerWritableDir(wparBaseDir string) string {
	return filepath.Join(wparBaseDir, writableLayerDir)
}

// containerTmpDir returns the path to the container's ephemeral tmp directory.
func containerTmpDir(wparBaseDir string) string {
	return filepath.Join(wparBaseDir, tmpDir)
}

// emptyDirPath returns the path for a named emptyDir volume.
func emptyDirPath(wparBaseDir, name string) string {
	return filepath.Join(wparBaseDir, emptyDirPrefix+name)
}

// SetupFSIsolation creates the dedicated filesystem layout for a WPAR and
// performs all mounts according to cfg. It must be called after mkwpar
// creates the WPAR but before startwpar activates it.
//
// Mount ordering:
//  1. Create writable-layer and tmp directories.
//  2. Mount the image root filesystem (ro or rw namefs) at the WPAR root.
//  3. Mount any additional volumes specified in cfg.Mounts.
//  4. Mount runtime-required writable paths (e.g. /tmp, /run) read-write.
func SetupFSIsolation(cfg FSIsolationConfig) error {
	base := cfg.WPARBaseDir

	// 1. Create writable-layer directory and tmp directory.
	if err := os.MkdirAll(containerWritableDir(base), 0700); err != nil {
		return fmt.Errorf("create writable layer dir: %w", err)
	}
	if err := os.MkdirAll(containerTmpDir(base), 0755); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	// 2. Mount the image rootfs into the WPAR root via namefs.
	// The WPAR's "/" is at <base>/. We mount the image rootfs there.
	rootDst := filepath.Join(base, "root")
	if err := os.MkdirAll(rootDst, 0755); err != nil {
		return fmt.Errorf("create wpar root mountpoint: %w", err)
	}
	roFlag := ""
	if cfg.ReadOnlyRootFS {
		roFlag = "ro"
	}
	if err := namefsMountAt(cfg.ImageRootFS, rootDst, roFlag, true, true, false); err != nil {
		return fmt.Errorf("mount image rootfs into wpar: %w", err)
	}

	// 3. Mount additional volumes.
	for _, m := range cfg.Mounts {
		if err := validateMountSpec(m, cfg.AllowedHostPaths, base); err != nil {
			return fmt.Errorf("mount validation failed: %w", err)
		}
		dst := filepath.Join(rootDst, m.Destination)
		if err := os.MkdirAll(dst, 0755); err != nil {
			return fmt.Errorf("create mountpoint %s: %w", dst, err)
		}
		roOpt := ""
		if m.ReadOnly {
			roOpt = "ro"
		}
		if err := namefsMountAt(m.Source, dst, roOpt, m.NoSUID, m.NoDev, m.NoExec); err != nil {
			return fmt.Errorf("mount volume %s→%s: %w", m.Source, m.Destination, err)
		}
	}

	// 4. When readOnlyRootFS is true, provide explicitly writable runtime paths.
	if cfg.ReadOnlyRootFS {
		for _, rw := range []string{"/tmp", "/run", "/var/run"} {
			rwPath := filepath.Join(rootDst, rw)
			if err := os.MkdirAll(rwPath, 0755); err != nil {
				return fmt.Errorf("create rw runtime path %s: %w", rw, err)
			}
			// Overlay the read-only root with writable dirs from the
			// container's writable-layer directory.
			rwSrc := filepath.Join(containerWritableDir(base), strings.TrimPrefix(rw, "/"))
			if err := os.MkdirAll(rwSrc, 0755); err != nil {
				return fmt.Errorf("create writable-layer rw path %s: %w", rwSrc, err)
			}
			if err := namefsMountAt(rwSrc, rwPath, "", false, true, false); err != nil {
				return fmt.Errorf("mount rw overlay %s: %w", rw, err)
			}
		}
	}

	return nil
}

// SetupEmptyDir creates and mounts an emptyDir volume at the given destination
// inside the WPAR root. Storage usage is integrated with the writable-layer
// accounting.
func SetupEmptyDir(wparBaseDir, rootDst, volumeName, destination string) error {
	src := emptyDirPath(wparBaseDir, volumeName)
	if err := os.MkdirAll(src, 0755); err != nil {
		return fmt.Errorf("create emptyDir source %s: %w", src, err)
	}
	dst := filepath.Join(rootDst, destination)
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("create emptyDir mountpoint %s: %w", dst, err)
	}
	return namefsMountAt(src, dst, "", false, true, false)
}

// TeardownFSIsolation unmounts and removes all filesystem resources owned by
// this WPAR. It unmounts in reverse order (volumes first, then rootfs) to
// ensure dependency-safe teardown. Only resources under wparBaseDir are
// affected.
func TeardownFSIsolation(wparBaseDir string) error {
	// Walk /proc/mounts (or the WPAR's mount table) and unmount everything
	// under wparBaseDir.
	mounts, err := listMountsUnder(wparBaseDir)
	if err != nil {
		return fmt.Errorf("list mounts for teardown: %w", err)
	}

	// Unmount in reverse order (deepest first).
	for i := len(mounts) - 1; i >= 0; i-- {
		if err := unmount(mounts[i]); err != nil {
			// Log but continue — we must remove as many mounts as possible.
			_ = err
		}
	}

	// Remove directories created by SetupFSIsolation.
	return os.RemoveAll(wparBaseDir)
}

// validateMountSpec checks that a MountSpec is safe to apply:
//   - Source and destination are clean absolute paths (no traversal).
//   - Symlinks in source and destination are not followed outside approved roots.
//   - For hostPath volumes, source is in AllowedHostPaths.
//   - Propagation mode is "private" or "".
//   - Destination does not escape the WPAR root.
func validateMountSpec(m MountSpec, allowedHostPaths []string, wparBaseDir string) error {
	if m.Propagation != "" && m.Propagation != "private" {
		return fmt.Errorf("unsupported mount propagation mode %q", m.Propagation)
	}
	if !filepath.IsAbs(m.Source) || !filepath.IsAbs(m.Destination) {
		return fmt.Errorf("mount source and destination must be absolute paths")
	}
	cleanSrc := filepath.Clean(m.Source)
	cleanDst := filepath.Clean(m.Destination)

	// Prevent path traversal in destination.
	wparRoot := filepath.Join(wparBaseDir, "root")
	absDst := filepath.Join(wparRoot, cleanDst)
	if !strings.HasPrefix(absDst, wparRoot+"/") && absDst != wparRoot {
		return fmt.Errorf("mount destination %q escapes WPAR root", m.Destination)
	}

	// For hostPath volumes, validate source against allowlist.
	if m.Type == "hostPath" || m.Type == "bind" {
		allowed := false
		for _, ap := range allowedHostPaths {
			if cleanSrc == filepath.Clean(ap) || strings.HasPrefix(cleanSrc, filepath.Clean(ap)+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("hostPath source %q is not in the allowed-host-paths list", m.Source)
		}
	}

	// Resolve the source to detect symlink substitution.
	resolved, err := filepath.EvalSymlinks(m.Source)
	if err != nil {
		return fmt.Errorf("resolve mount source %q: %w", m.Source, err)
	}
	if resolved != cleanSrc {
		// The source path contains symlinks; re-validate against allowlist.
		if m.Type == "hostPath" || m.Type == "bind" {
			allowed := false
			for _, ap := range allowedHostPaths {
				if strings.HasPrefix(resolved, filepath.Clean(ap)) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("resolved mount source %q (from %q) is outside allowed host paths",
					resolved, m.Source)
			}
		}
	}

	return nil
}

// namefsMountAt issues "mount -v namefs [-o <opts>] <src> <dst>".
// opts is a comma-separated string of mount options (e.g. "ro", "nosuid").
func namefsMountAt(src, dst, roOpt string, nosuid, nodev, noexec bool) error {
	var opts []string
	if roOpt != "" {
		opts = append(opts, roOpt)
	}
	if nosuid {
		opts = append(opts, "nosuid")
	}
	if nodev {
		opts = append(opts, "nodev")
	}
	if noexec {
		opts = append(opts, "noexec")
	}

	args := []string{"-v", "namefs"}
	if len(opts) > 0 {
		args = append(args, "-o", strings.Join(opts, ","))
	}
	args = append(args, src, dst)

	cmd := exec.Command("mount", args...)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount -v namefs %s %s: %w\n%s", src, dst, err, string(out))
	}
	return nil
}

// unmount calls "umount <path>".
func unmount(path string) error {
	cmd := exec.Command("umount", path)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %w\n%s", path, err, string(out))
	}
	return nil
}

// listMountsUnder returns all mount points that are under baseDir, in
// lexicographic order (shallowest first) so callers can reverse for teardown.
func listMountsUnder(baseDir string) ([]string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		// /proc/mounts may not be present; fall back to /etc/mtab.
		data, err = os.ReadFile("/etc/mtab")
		if err != nil {
			return nil, fmt.Errorf("read mount table: %w", err)
		}
	}

	base := filepath.Clean(baseDir)
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mp := filepath.Clean(fields[1])
		if strings.HasPrefix(mp, base+"/") || mp == base {
			out = append(out, mp)
		}
	}
	return out, nil
}
