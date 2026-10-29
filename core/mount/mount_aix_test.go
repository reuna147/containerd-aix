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

import "testing"

func TestIsUmountNotMounted(t *testing.T) {
	tests := []struct {
		desc   string
		output string
		want   bool
	}{
		{
			desc:   "AIX 0506-349 message",
			output: "umount: 0506-349 /mnt/foo is not a mount point.",
			want:   true,
		},
		{
			desc:   "not a mount message",
			output: "not a mount point",
			want:   true,
		},
		{
			desc:   "EINVAL in output",
			output: "umount: EINVAL",
			want:   true,
		},
		{
			desc:   "busy message is not not-mounted",
			output: "umount: device is busy",
			want:   false,
		},
		{
			desc:   "unknown error is not not-mounted",
			output: "umount: some other error",
			want:   false,
		},
		{
			desc:   "empty output",
			output: "",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := isUmountNotMounted(tc.output)
			if got != tc.want {
				t.Errorf("isUmountNotMounted(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

func TestIsUmountBusy(t *testing.T) {
	tests := []struct {
		desc   string
		output string
		want   bool
	}{
		{
			desc:   "device is busy",
			output: "umount: device is busy",
			want:   true,
		},
		{
			desc:   "EBUSY in output",
			output: "umount: EBUSY: resource busy",
			want:   true,
		},
		{
			desc:   "not-mounted message is not busy",
			output: "umount: 0506-349 not a mount point",
			want:   false,
		},
		{
			desc:   "unknown error is not busy",
			output: "umount: permission denied",
			want:   false,
		},
		{
			desc:   "empty output",
			output: "",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := isUmountBusy(tc.output)
			if got != tc.want {
				t.Errorf("isUmountBusy(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
