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

// containerd-shim-wpar-v1 is the containerd v2 shim for AIX Workload Partitions.
//
// It is launched by containerd's shim manager for each task whose runtime is
// "io.containerd.wpar.v1". It implements the containerd task v3 ttrpc API,
// delegating all lifecycle operations to the AIX WPAR management tools
// (mkwpar, startwpar, stopwpar, rmwpar, lswpar, clogin).
//
// Usage (handled by containerd, not directly by users):
//
//	containerd-shim-wpar-v1 -namespace <ns> -id <id> -address <addr> start
//	containerd-shim-wpar-v1 -namespace <ns> -id <id> [-bundle <path>] delete
//	containerd-shim-wpar-v1 -info
//	containerd-shim-wpar-v1 -version
package main

import (
	"context"

	"github.com/containerd/containerd/v2/internal/wpar"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
)

func init() {
	// Register the WPAR task service as a TTRPCPlugin.
	// shim.RunShim will automatically discover TTRPCPlugin instances and call
	// RegisterTTRPC on each one.
	registry.Register(&plugin.Registration{
		Type: plugins.TTRPCPlugin,
		ID:   "task",
		Requires: []plugin.Type{
			plugins.EventPlugin,
			plugins.InternalPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (any, error) {
			pp, err := ic.GetByID(plugins.EventPlugin, "publisher")
			if err != nil {
				return nil, err
			}
			ss, err := ic.GetByID(plugins.InternalPlugin, "shutdown")
			if err != nil {
				return nil, err
			}
			// Cast to shim.Publisher (events.Publisher + io.Closer), matching
			// the concrete type that the shim framework actually injects.
			return wpar.NewService(ic.Context, pp.(shim.Publisher), ss.(shutdown.Service))
		},
	})
}

func main() {
	shim.RunShim(context.Background(), wpar.NewManager(wpar.RuntimeName))
}
