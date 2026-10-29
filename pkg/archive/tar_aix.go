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

package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"syscall"

	"github.com/containerd/continuity/fs"
	"github.com/containerd/continuity/sysx"
	"github.com/moby/sys/userns"
	"golang.org/x/sys/unix"
)

func chmodTarEntry(perm os.FileMode) os.FileMode {
	return perm
}

func setHeaderForSpecialDevice(hdr *tar.Header, name string, fi os.FileInfo) error {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported stat type")
	}

	rdev := uint64(s.Rdev)

	if s.Mode&syscall.S_IFBLK != 0 ||
		s.Mode&syscall.S_IFCHR != 0 {
		hdr.Devmajor = int64(unix.Major(rdev))
		hdr.Devminor = int64(unix.Minor(rdev))
	}

	return nil
}

func open(p string) (*os.File, error) {
	return os.Open(p)
}

func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	// Call chmod to avoid permission mask
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return nil, err
	}
	return f, err
}

func mkdir(path string, perm os.FileMode) error {
	if err := os.Mkdir(path, perm); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}

func skipFile(hdr *tar.Header) bool {
	switch hdr.Typeflag {
	case tar.TypeBlock, tar.TypeChar:
		return userns.RunningInUserNS()
	default:
		return false
	}
}

// handleTarTypeBlockCharFifo handles Block, Char and Fifo tar header types.
func handleTarTypeBlockCharFifo(hdr *tar.Header, path string) error {
	mode := uint32(hdr.Mode & 07777)
	switch hdr.Typeflag {
	case tar.TypeBlock:
		mode |= unix.S_IFBLK
	case tar.TypeChar:
		mode |= unix.S_IFCHR
	case tar.TypeFifo:
		mode |= unix.S_IFIFO
	}

	if hdr.Devmajor < 0 || hdr.Devmajor > math.MaxUint32 ||
		hdr.Devminor < 0 || hdr.Devminor > math.MaxUint32 {
		return fmt.Errorf("device number %d:%d for %q out of range: %w", hdr.Devmajor, hdr.Devminor, hdr.Name, errInvalidArchive)
	}

	return mknod(path, mode, unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))
}

// mknod wraps unix.Mknod and casts dev to int.
func mknod(path string, mode uint32, dev uint64) error {
	return unix.Mknod(path, mode, int(dev))
}

// lsetxattrCreate sets an xattr, ignoring ENOTSUP and EEXIST.
// AIX does not expose unix.XATTR_CREATE; we call sysx.LSetxattr with flags=0.
func lsetxattrCreate(link string, attr string, data []byte) error {
	err := sysx.LSetxattr(link, attr, data, 0)
	if err == unix.ENOTSUP || err == sysx.ENODATA {
		return nil
	}
	return err
}

// lchmod changes the mode of a file, skipping symlinks.
func lchmod(path string, mode os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func getxattr(path, attr string) ([]byte, error) {
	b, err := sysx.LGetxattr(path, attr)
	if err == unix.ENOTSUP || err == sysx.ENODATA {
		return nil, nil
	}
	return b, err
}

func setxattr(path, key, value string) error {
	if strings.HasPrefix(key, "trusted.") {
		return fmt.Errorf("admin attributes from archive not supported: %w", unix.ENOTSUP)
	}
	return sysx.LSetxattr(path, key, []byte(value), 0)
}

func copyDirInfo(fi os.FileInfo, path string) error {
	st := fi.Sys().(*syscall.Stat_t)
	if err := os.Lchown(path, int(st.Uid), int(st.Gid)); err != nil {
		if os.IsPermission(err) {
			if dstStat, err2 := os.Lstat(path); err2 == nil {
				st2 := dstStat.Sys().(*syscall.Stat_t)
				if st.Uid == st2.Uid && st.Gid == st2.Gid {
					err = nil
				}
			}
		}
		if err != nil {
			return fmt.Errorf("failed to chown %s: %w", path, err)
		}
	}

	if err := os.Chmod(path, fi.Mode()); err != nil {
		return fmt.Errorf("failed to chmod %s: %w", path, err)
	}

	timespec := []unix.Timespec{
		unix.NsecToTimespec(syscall.TimespecToNsec(fs.StatAtime(st))),
		unix.NsecToTimespec(syscall.TimespecToNsec(fs.StatMtime(st))),
	}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, timespec, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("failed to utime %s: %w", path, err)
	}

	return nil
}

func copyUpXAttrs(dst, src string) error {
	xattrKeys, err := sysx.LListxattr(src)
	if err != nil {
		if err == unix.ENOTSUP || err == sysx.ENODATA {
			return nil
		}
		return fmt.Errorf("failed to list xattrs on %s: %w", src, err)
	}
	for _, xattr := range xattrKeys {
		if strings.HasPrefix(xattr, "trusted.") {
			continue
		}
		data, err := sysx.LGetxattr(src, xattr)
		if err != nil {
			if err == unix.ENOTSUP || err == sysx.ENODATA {
				continue
			}
			return fmt.Errorf("failed to get xattr %q on %s: %w", xattr, src, err)
		}
		if err := lsetxattrCreate(dst, xattr, data); err != nil {
			return fmt.Errorf("failed to set xattr %q on %s: %w", xattr, dst, err)
		}
	}

	return nil
}
