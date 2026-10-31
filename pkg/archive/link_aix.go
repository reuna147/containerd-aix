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
	"os"
)

// link creates a hard link from oldname to newname.
//
// On AIX, link(2) follows symlinks: os.Link(symlink, new) creates a hard link
// to the symlink's target, not to the symlink itself.  This means a layer that
// carries a symlink pointing outside the extraction root, followed by a hard
// link to that symlink, would create a hard link to an external file — allowing
// later layer entries to modify it.  See bob-security-note-2026-10-29.md.
//
// We work around this by lstat-ing the source.  If it is a symlink, we
// recreate it with Readlink + Symlink rather than hard-linking it, which
// preserves the extraction semantics without following the symlink target.
func link(oldname, newname string) error {
	fi, err := os.Lstat(oldname)
	if err != nil {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: err}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// oldname is a symlink — recreate rather than hard-link (which would
		// follow it on AIX, potentially escaping the extraction root).
		target, err := os.Readlink(oldname)
		if err != nil {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: err}
		}
		return os.Symlink(target, newname)
	}
	// Regular file or other non-symlink: os.Link is safe.
	return os.Link(oldname, newname)
}
