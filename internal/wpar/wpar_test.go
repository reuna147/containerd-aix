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
	"strings"
	"testing"
)

func TestWparName(t *testing.T) {
	tests := []struct {
		desc  string
		input string
		// check is a function so we can assert properties rather than exact strings
		check func(t *testing.T, name string)
	}{
		{
			desc:  "short lowercase id stays as-is (with prefix)",
			input: "abc",
			check: func(t *testing.T, name string) {
				if name != "wabc" {
					t.Errorf("got %q, want %q", name, "wabc")
				}
			},
		},
		{
			desc:  "64-char hex CRI id is truncated to 25 chars",
			input: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			check: func(t *testing.T, name string) {
				if len(name) != 25 {
					t.Errorf("len(%q) = %d, want 25", name, len(name))
				}
				if name[0] != 'w' {
					t.Errorf("name %q must start with 'w'", name)
				}
			},
		},
		{
			desc:  "id starting with a digit gets 'w' prefix and is capped at 25",
			input: "0deadbeefcafe1234567890ab",
			check: func(t *testing.T, name string) {
				if name[0] != 'w' {
					t.Errorf("name %q must start with 'w'", name)
				}
				if len(name) > 25 {
					t.Errorf("len(%q) = %d, want ≤25", name, len(name))
				}
			},
		},
		{
			desc:  "characters outside [a-zA-Z0-9_-] are replaced with underscore",
			input: "hello world!@#",
			check: func(t *testing.T, name string) {
				for _, c := range name {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') || c == '_' || c == '-') {
						t.Errorf("illegal character %q in name %q", c, name)
					}
				}
			},
		},
		{
			desc:  "always starts with a letter even when input starts with digit",
			input: "123abc",
			check: func(t *testing.T, name string) {
				if name[0] < 'a' || name[0] > 'z' {
					if name[0] < 'A' || name[0] > 'Z' {
						t.Errorf("name %q does not start with a letter", name)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			name := wparName(tc.input)
			tc.check(t, name)
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's a test", "'it'\\''s a test'"},
		{"", "''"},
		{"/usr/bin/env", "'/usr/bin/env'"},
		{"VAR=value with spaces", "'VAR=value with spaces'"},
		{"it's 'quoted'", "'it'\\''s '\\''quoted'\\'''"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := shellQuote(tc.input)
			if got != tc.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tc.input, got, tc.want)
			}
			// Verify that the output, when evaluated by a shell, is safe:
			// it should not contain unescaped single quotes outside of the
			// '\'' pattern.
			stripped := strings.ReplaceAll(got, "\\'", "")
			// After removing all \' sequences, the remaining single quotes
			// should appear in matched pairs (opening and closing of 'literal').
			count := strings.Count(stripped, "'")
			if count%2 != 0 {
				t.Errorf("shellQuote(%q) = %q has unbalanced quotes after stripping escapes", tc.input, got)
			}
		})
	}
}
