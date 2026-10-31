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

package local

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// syncDir syncs the directory metadata on AIX.
//
// JFS2 journals directory updates internally, so fsync(2) on a directory
// descriptor returns EINVAL. Treat that as "not needed" rather than an error,
// matching the documented JFS2 behaviour.
func syncDir(dir string) error {
	dirF, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open dir %s: %w", dir, err)
	}
	err = dirF.Sync()
	dirF.Close()
	if err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("failed to sync dir %s: %w", dir, err)
	}
	return nil
}
