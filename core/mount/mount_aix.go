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

package mount

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// mount performs a namefs bind mount on AIX.
//
// AIX has no Mount(2) wrapper in x/sys/unix. The shell equivalent is:
//
//	mount -v namefs [-o ro[,nosuid]] /src /dst
//
// The command can intermittently return ECHILD because of signal handling in
// the shim (the same issue affects FreeBSD); we retry up to 10 times.
func (m *Mount) mount(target string) error {
	// Build the argument list: mount -v namefs [-o opt,...] <source> <target>
	args := []string{"-v", "namefs"}
	if len(m.Options) > 0 {
		opts := m.Options[0]
		for _, o := range m.Options[1:] {
			opts += "," + o
		}
		args = append(args, "-o", opts)
	}
	args = append(args, m.Source, target)

	const retriesOnECHILD = 10
	for range retriesOnECHILD {
		cmd := exec.Command("mount", args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.ECHILD) {
			return fmt.Errorf("mount [%v] failed: %q: %w", args, string(out), err)
		}
		// ECHILD: we do not know if the mount completed. Check by stat.
		isMounted, checkErr := mountinfo.Mounted(target)
		if checkErr == nil && isMounted {
			return nil
		}
	}
	return fmt.Errorf("mount [%v] failed with ECHILD (retried %d times)", args, retriesOnECHILD)
}

// unmount unmounts a namefs mount point by running umount(8).
//
// umount(2) on AIX requires a block device and fails with ENOTBLK on namefs
// mount points. umount(8) does work. We preserve the callers' expected errno
// semantics: EINVAL when nothing is mounted there, retry on EBUSY.
func unmount(target string, _ int) error {
	for range 50 {
		out, err := exec.Command("umount", target).CombinedOutput()
		if err == nil {
			return nil
		}
		// umount(8) exits with status 1. Inspect the output for known conditions.
		outStr := string(out)
		switch {
		case isUmountNotMounted(outStr):
			return unix.EINVAL
		case isUmountBusy(outStr):
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return fmt.Errorf("umount %s: %w\n%s", target, err, outStr)
	}
	return fmt.Errorf("failed to unmount target %s: %w", target, unix.EBUSY)
}

// isUmountNotMounted returns true when umount(8) reports that the path is not
// a mount point (AIX error 0506-349 or EINVAL from the underlying syscall).
func isUmountNotMounted(output string) bool {
	return strings.Contains(output, "0506-349") ||
		strings.Contains(output, "not a mount") ||
		strings.Contains(output, "EINVAL")
}

// isUmountBusy returns true when umount(8) reports the filesystem is busy.
func isUmountBusy(output string) bool {
	return strings.Contains(output, "busy") || strings.Contains(output, "EBUSY")
}

// Unmount unmounts the given path. EINVAL (nothing mounted there) is silenced.
func Unmount(target string, flags int) error {
	if err := unmount(target, flags); err != nil && err != unix.EINVAL {
		return err
	}
	return nil
}

// UnmountAll repeatedly unmounts the given mount point until EINVAL is returned
// (nothing more to unmount). Noop for empty or non-existent paths.
func UnmountAll(mount string, flags int) error {
	if mount == "" {
		return nil
	}
	if _, err := os.Stat(mount); os.IsNotExist(err) {
		return nil
	}

	for {
		if err := unmount(mount, flags); err != nil {
			// EINVAL means nothing is mounted there — we are done.
			if err == unix.EINVAL {
				return nil
			}
			return err
		}
	}
}

// UnmountRecursive unmounts the target and all mounts underneath it, starting
// with the deepest mount first.
func UnmountRecursive(target string, flags int) error {
	if target == "" {
		return nil
	}

	target, err := CanonicalizePath(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	mounts, err := mountinfo.GetMounts(mountinfo.PrefixFilter(target))
	if err != nil {
		return err
	}

	targetSet := make(map[string]struct{})
	for _, m := range mounts {
		targetSet[m.Mountpoint] = struct{}{}
	}

	var targets []string
	for m := range targetSet {
		targets = append(targets, m)
	}

	// Deepest mount first.
	sort.SliceStable(targets, func(i, j int) bool {
		return len(targets[i]) > len(targets[j])
	})

	for i, t := range targets {
		if err := UnmountAll(t, flags); err != nil {
			if i == len(targets)-1 {
				return err
			}
		}
	}
	return nil
}

// isFUSE is a no-op on AIX; FUSE is not supported.
func isFUSE(_ string) bool { return false }

// unmountFUSE is a no-op on AIX.
func unmountFUSE(_ string) error {
	return syscall.ENOSYS
}
