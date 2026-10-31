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

package commands

import (
	"os"
	"syscall"
)

// canIgnoreSignal returns true for signals that should not be forwarded to
// the container task.  On AIX, SIGURG (16) is Go's internal goroutine
// preemption signal and must never be forwarded — it has the same number as
// SIGIOINT, and forwarding it would send an unwanted interrupt to the task on
// every Go scheduler preemption.
func canIgnoreSignal(s os.Signal) bool {
	return s == syscall.SIGURG
}
