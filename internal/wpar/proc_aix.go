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
	"os"
	"os/exec"
	"syscall"
)

// setSysProcAttr configures the shim child process to start a new session
// so it is detached from the parent process group and survives the parent exit.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

// syscallSignal converts a uint32 signal number to os.Signal.
func syscallSignal(sig uint32) os.Signal {
	return syscall.Signal(sig)
}
