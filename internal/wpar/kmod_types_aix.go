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

// Package wpar — kmod_types_aix.go
//
// Pure-Go types and policy manager for the per-WPAR syscall bitmap.
// This file has no CGO and compiles under CGO_ENABLED=0, which allows the
// rest of the package to type-check without a C compiler.
//
// The CGO libc ioctl(2) call is in kmod_util.go (CGO required, GOOS=aix).

package wpar

import (
	"fmt"
	"os"
	"sync"
)

const (
	// SyscallBitmapWords is the number of 64-bit words in the syscall policy
	// bitmap. AIX has fewer than 512 syscalls; 8 words × 64 bits = 512 slots.
	SyscallBitmapWords = 8

	// kmodDevice is the character device exposed by the kernel extension.
	kmodDevice = "/dev/wpar_kmod"
)

// kmodPolicyClient is the interface that KmodPolicyManager uses to talk to
// the kernel extension. The concrete implementation (*KmodClient) lives in
// kmod_util.go and requires CGO; this interface lets the manager compile
// under CGO_ENABLED=0.
type kmodPolicyClient interface {
	SetPolicy(wparID uint32, bitmap SyscallBitmap) error
	RemovePolicy(wparID uint32) error
}

// KmodClient manages the file descriptor to /dev/wpar_kmod.
// Its methods (SetPolicy, RemovePolicy, QueryPolicy) are defined in
// kmod_util.go which requires CGO.
type KmodClient struct {
	mu  sync.Mutex
	dev *os.File
}

// SyscallBitmap is an array of 64-bit words forming a compact bitmask of
// allowed (1) or denied (0) syscalls indexed by AIX syscall number.
type SyscallBitmap [SyscallBitmapWords]uint64

// Allow marks syscall number n as permitted in the bitmap.
func (b *SyscallBitmap) Allow(n uint16) {
	if int(n) < SyscallBitmapWords*64 {
		b[n/64] |= 1 << (n % 64)
	}
}

// Deny marks syscall number n as denied (returns EPERM) in the bitmap.
func (b *SyscallBitmap) Deny(n uint16) {
	if int(n) < SyscallBitmapWords*64 {
		b[n/64] &^= 1 << (n % 64)
	}
}

// IsAllowed returns true when syscall number n is permitted.
func (b SyscallBitmap) IsAllowed(n uint16) bool {
	if int(n) >= SyscallBitmapWords*64 {
		return false
	}
	return b[n/64]&(1<<(n%64)) != 0
}

// DefaultAllowBitmap returns a bitmap with all syscalls allowed (permissive
// default). Workloads whose policy has not been explicitly configured fall back
// to this bitmap.
func DefaultAllowBitmap() SyscallBitmap {
	var b SyscallBitmap
	for i := range b {
		b[i] = ^uint64(0)
	}
	return b
}

// DefaultDenyBitmap returns a bitmap with all syscalls denied (fail-closed
// default used for WPARs that have not completed their startup sequence).
func DefaultDenyBitmap() SyscallBitmap {
	return SyscallBitmap{}
}

// KmodPolicyManager wraps a kmodPolicyClient with WPAR-keyed policy lifecycle.
// It is the primary interface used by the shim to manage per-WPAR syscall policies.
type KmodPolicyManager struct {
	mu     sync.Mutex
	client kmodPolicyClient         // nil in unit-test mode (in-memory only)
	active map[uint32]SyscallBitmap // wparID → current bitmap
}

// NewKmodPolicyManager creates a KmodPolicyManager backed by c.
// c may be nil for unit-test mode (in-memory only, no real ioctl).
func NewKmodPolicyManager(c kmodPolicyClient) *KmodPolicyManager {
	return &KmodPolicyManager{
		client: c,
		active: make(map[uint32]SyscallBitmap),
	}
}

// Activate registers the given bitmap for wparID. It fails if any required
// syscall interception could not be registered (the kernel extension returns
// ENOSYS for syscalls it cannot intercept). The policy is installed before
// the container process is released.
// When client is nil (unit-test mode), the bitmap is stored in-memory only.
func (m *KmodPolicyManager) Activate(wparID uint32, bitmap SyscallBitmap) error {
	if m.client != nil {
		if err := m.client.SetPolicy(wparID, bitmap); err != nil {
			return fmt.Errorf("kmod: activate policy for wpar %d: %w", wparID, err)
		}
	}
	m.mu.Lock()
	m.active[wparID] = bitmap
	m.mu.Unlock()
	return nil
}

// Replace atomically replaces the running policy for wparID. Concurrent
// threads in the WPAR cannot observe partially updated policy.
// When client is nil (unit-test mode), the bitmap is stored in-memory only.
func (m *KmodPolicyManager) Replace(wparID uint32, bitmap SyscallBitmap) error {
	if m.client != nil {
		if err := m.client.SetPolicy(wparID, bitmap); err != nil {
			return fmt.Errorf("kmod: replace policy for wpar %d: %w", wparID, err)
		}
	}
	m.mu.Lock()
	m.active[wparID] = bitmap
	m.mu.Unlock()
	return nil
}

// Deactivate removes the policy for wparID. Returns EBUSY if the kernel
// extension reports that protected processes are still running.
// When client is nil (unit-test mode), the entry is simply deleted.
func (m *KmodPolicyManager) Deactivate(wparID uint32) error {
	if m.client != nil {
		if err := m.client.RemovePolicy(wparID); err != nil {
			return fmt.Errorf("kmod: deactivate policy for wpar %d: %w", wparID, err)
		}
	}
	m.mu.Lock()
	delete(m.active, wparID)
	m.mu.Unlock()
	return nil
}

// IsActive returns true if wparID has a registered policy.
func (m *KmodPolicyManager) IsActive(wparID uint32) bool {
	m.mu.Lock()
	_, ok := m.active[wparID]
	m.mu.Unlock()
	return ok
}
