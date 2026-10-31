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

// Package wpar — kmod_util.go
//
// Implements the userspace side of the per-WPAR syscall interception policy.
// The kernel extension (kmod_util.kext) exposes a character device at
// /dev/wpar_kmod through which the runtime:
//
//   - Registers a compact bitmap policy indexed by AIX syscall number for each
//     WPAR (identified by WPAR ID, not by PID/TID).
//   - Replaces policies atomically so no concurrent thread sees partial state.
//   - Removes policies when the container is destroyed, but only after all
//     protected workload processes have exited.
//
// Design constraints from the directives:
//   - Policy lookup in the syscall hot path must be read-only; no memory
//     allocation, no blocking locks, no I/O in the kernel handler.
//   - Policies are bound to WPAR identity, not to individual PIDs or TIDs.
//   - Every process/thread in a WPAR — including those created through fork,
//     exec, and supported thread-creation mechanisms — is covered immediately.
//   - Policy replacement is atomic.
//   - Policy removal is rejected while protected workload processes remain active.
//   - Denied syscalls cause the pre-syscall handler to abort execution with EPERM.
//
// The device protocol uses fixed-size binary messages (KmodRequest) that are
// written to /dev/wpar_kmod with ioctl(2). The kernel extension parses them
// entirely in kernel space; policy translation and validation happen here in
// userspace before the ioctl is issued.

package wpar

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// kmodDevice is the character device exposed by the kernel extension.
	kmodDevice = "/dev/wpar_kmod"

	// SyscallBitmapWords is the number of 64-bit words in the syscall policy
	// bitmap. AIX has fewer than 512 syscalls; 8 words × 64 bits = 512 slots.
	SyscallBitmapWords = 8

	// kmodMagic is the ioctl type byte for the WPAR kmod device.
	kmodMagic = 'W'

	// ioctl command numbers (must match the kernel extension header).
	kmodIocSetPolicy    = 0x01
	kmodIocRemovePolicy = 0x02
	kmodIocQueryPolicy  = 0x03
)

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
func (b *SyscallBitmap) IsAllowed(n uint16) bool {
	if int(n) >= SyscallBitmapWords*64 {
		return false
	}
	return b[n/64]&(1<<(n%64)) != 0
}

// kmodRequest is the fixed-size binary message written to /dev/wpar_kmod.
// Total size: 4 (op) + 4 (wpar_id) + 64 (bitmap) + 4 (flags) = 76 bytes.
// The kernel extension must define an identical struct.
type kmodRequest struct {
	Op     uint32
	WparID uint32
	Bitmap SyscallBitmap // 8 × uint64 = 64 bytes
	Flags  uint32
}

// kmodRequestSize is the wire size of kmodRequest.
const kmodRequestSize = 4 + 4 + SyscallBitmapWords*8 + 4

// KmodClient manages the file descriptor to /dev/wpar_kmod.
// It is safe for concurrent use.
type KmodClient struct {
	mu  sync.Mutex
	dev *os.File
}

// defaultKmodClient is the package-level singleton used by the WPAR lifecycle
// functions. Replaced in tests via setKmodClient.
var (
	globalKmodMu     sync.Mutex
	globalKmodClient *KmodClient
)

// openKmodClient opens /dev/wpar_kmod and stores the resulting client as the
// package singleton. Must be called once during runtime startup before any
// WPAR is created.
func openKmodClient() (*KmodClient, error) {
	f, err := os.OpenFile(kmodDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open kmod device %s: %w", kmodDevice, err)
	}
	c := &KmodClient{dev: f}
	globalKmodMu.Lock()
	globalKmodClient = c
	globalKmodMu.Unlock()
	return c, nil
}

// getKmodClient returns the global KmodClient or an error if not initialised.
func getKmodClient() (*KmodClient, error) {
	globalKmodMu.Lock()
	c := globalKmodClient
	globalKmodMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("kmod client not initialised; call openKmodClient first")
	}
	return c, nil
}

// Close releases the device file descriptor.
func (c *KmodClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dev != nil {
		err := c.dev.Close()
		c.dev = nil
		return err
	}
	return nil
}

// SetPolicy registers or replaces the syscall bitmap policy for the given WPAR.
// The replacement is atomic from the kernel extension's perspective.
// This function must be called before the container's initial process is
// released from its startup stop.
func (c *KmodClient) SetPolicy(wparID uint32, bitmap SyscallBitmap) error {
	req := kmodRequest{
		Op:     kmodIocSetPolicy,
		WparID: wparID,
		Bitmap: bitmap,
	}
	return c.ioctl(req)
}

// RemovePolicy removes the syscall policy for the given WPAR.
// The kernel extension rejects this request while protected workload processes
// remain active (returns EBUSY). The caller must ensure all processes have
// exited before calling RemovePolicy.
func (c *KmodClient) RemovePolicy(wparID uint32) error {
	req := kmodRequest{
		Op:     kmodIocRemovePolicy,
		WparID: wparID,
	}
	return c.ioctl(req)
}

// QueryPolicy retrieves the current bitmap policy for the given WPAR.
// Returns ErrNotFound when no policy has been registered for that WPAR.
func (c *KmodClient) QueryPolicy(wparID uint32) (SyscallBitmap, error) {
	req := kmodRequest{
		Op:     kmodIocQueryPolicy,
		WparID: wparID,
	}
	if err := c.ioctl(req); err != nil {
		return SyscallBitmap{}, err
	}
	// The kernel extension writes the result bitmap back into the same memory;
	// on AIX, ioctl uses the same buffer for in/out. We read it from req.
	return req.Bitmap, nil
}

// ioctl serialises the kmodRequest and writes it to the device fd using the
// WPAR_KMOD ioctl(2). The kernel extension processes the request synchronously.
func (c *KmodClient) ioctl(req kmodRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dev == nil {
		return fmt.Errorf("kmod device is closed")
	}

	// Serialise to a fixed-size byte slice using little-endian byte order,
	// matching the kernel extension's struct layout on AIX/ppc64.
	buf := make([]byte, kmodRequestSize)
	off := 0
	binary.LittleEndian.PutUint32(buf[off:], req.Op)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], req.WparID)
	off += 4
	for _, w := range req.Bitmap {
		binary.LittleEndian.PutUint64(buf[off:], w)
		off += 8
	}
	binary.LittleEndian.PutUint32(buf[off:], req.Flags)

	// Use IOWR-style ioctl: write the buffer to the device fd.
	// The ioctl number follows the AIX _IOWR macro convention.
	ioctlNum := ioctlNr(kmodMagic, req.Op, uint32(kmodRequestSize))
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		c.dev.Fd(),
		uintptr(ioctlNum),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if errno != 0 {
		return fmt.Errorf("kmod ioctl op=%d wpar=%d: %w", req.Op, req.WparID, errno)
	}

	// Copy result back for QueryPolicy (op 3) — the kernel wrote into buf.
	if req.Op == kmodIocQueryPolicy {
		off = 4 + 4 // skip Op and WparID
		for i := range req.Bitmap {
			req.Bitmap[i] = binary.LittleEndian.Uint64(buf[off:])
			off += 8
		}
	}
	return nil
}

// ioctlNr constructs an AIX ioctl number from type byte, command, and size.
// On AIX _IOWR(type, nr, size) = ((type)<<8 | (nr)) with size encoded
// in the upper 16 bits of the 32-bit number.
func ioctlNr(typ byte, nr uint32, size uint32) uint32 {
	return (uint32(typ) << 24) | (size << 8) | nr
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

// KmodPolicyManager wraps KmodClient with WPAR-keyed policy lifecycle. It is
// the primary interface used by the shim to manage per-WPAR syscall policies.
type KmodPolicyManager struct {
	mu      sync.Mutex
	client  *KmodClient
	active  map[uint32]SyscallBitmap // wparID → current bitmap
}

// NewKmodPolicyManager creates a KmodPolicyManager backed by c.
func NewKmodPolicyManager(c *KmodClient) *KmodPolicyManager {
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
