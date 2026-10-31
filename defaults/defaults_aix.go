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

package defaults

const (
	// DefaultAddress is the default unix socket address
	DefaultAddress = "/var/run/containerd/containerd.sock"
	// DefaultDebugAddress is the default unix socket address for pprof data
	DefaultDebugAddress = "/var/run/containerd/debug.sock"
	// DefaultFIFODir is the default location used by client-side cio library
	// to store FIFOs.
	DefaultFIFODir = "/var/run/containerd/fifo"
	// DefaultSnapshotter is the default snapshotter for AIX.
	DefaultSnapshotter = "native"
	// DefaultStateDir is the default location used by containerd to store
	// transient data
	DefaultStateDir = "/var/run/containerd"
	// DefaultDiffer is the default differ for AIX.
	DefaultDiffer = "walking"
	// DefaultRuntime is the default AIX runtime for running containers.
	// Uses the WPAR-based shim (containerd-shim-wpar-v1).
	DefaultRuntime = "io.containerd.wpar.v1"
)
