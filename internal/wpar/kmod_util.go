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
// Implements the KmodClient — the userspace side of the per-WPAR syscall
// interception policy. The kernel extension exposes a character device at
// /dev/wpar_kmod through which the runtime registers, replaces, and removes
// per-WPAR syscall bitmap policies.
//
// This file requires CGO (libc ioctl(2)). Pure-Go types and the policy manager
// live in kmod_types_aix.go so they compile under CGO_ENABLED=0.

package wpar

/*
#include <sys/ioctl.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"
)

const (
	// kmodMagic is the ioctl type byte for the WPAR kmod device.
	kmodMagic = 'W'

	// ioctl command numbers (must match the kernel extension header).
	kmodIocSetPolicy    = 0x01
	kmodIocRemovePolicy = 0x02
	kmodIocQueryPolicy  = 0x03
)

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

// globalKmodClient is the package-level singleton used by the WPAR lifecycle
// functions.
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
func (c *KmodClient) SetPolicy(wparID uint32, bitmap SyscallBitmap) error {
	req := kmodRequest{Op: kmodIocSetPolicy, WparID: wparID, Bitmap: bitmap}
	return c.ioctl(&req)
}

// RemovePolicy removes the syscall policy for the given WPAR.
func (c *KmodClient) RemovePolicy(wparID uint32) error {
	req := kmodRequest{Op: kmodIocRemovePolicy, WparID: wparID}
	return c.ioctl(&req)
}

// QueryPolicy retrieves the current bitmap policy for the given WPAR.
func (c *KmodClient) QueryPolicy(wparID uint32) (SyscallBitmap, error) {
	req := kmodRequest{Op: kmodIocQueryPolicy, WparID: wparID}
	if err := c.ioctl(&req); err != nil {
		return SyscallBitmap{}, err
	}
	return req.Bitmap, nil
}

// ioctl serialises the kmodRequest and issues libc ioctl(2) via cgo.
// AIX Go has no syscall.SYS_IOCTL constant; syscall.Syscall always returns
// EINVAL. We call libc ioctl(2) directly instead.
// Encoding is big-endian: AIX/ppc64 is big-endian.
func (c *KmodClient) ioctl(req *kmodRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dev == nil {
		return fmt.Errorf("kmod device is closed")
	}

	buf := make([]byte, kmodRequestSize)
	off := 0
	binary.BigEndian.PutUint32(buf[off:], req.Op)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], req.WparID)
	off += 4
	for _, w := range req.Bitmap {
		binary.BigEndian.PutUint64(buf[off:], w)
		off += 8
	}
	binary.BigEndian.PutUint32(buf[off:], req.Flags)

	ioctlNum := ioctlNr(kmodMagic, req.Op, uint32(kmodRequestSize))
	ret := C.ioctl(C.int(c.dev.Fd()), C.ulong(ioctlNum), unsafe.Pointer(&buf[0]))
	if ret != 0 {
		return fmt.Errorf("kmod ioctl op=%d wpar=%d: ioctl returned %d", req.Op, req.WparID, ret)
	}

	// Copy result back for QueryPolicy — kernel writes into buf.
	if req.Op == kmodIocQueryPolicy {
		off = 4 + 4
		for i := range req.Bitmap {
			req.Bitmap[i] = binary.BigEndian.Uint64(buf[off:])
			off += 8
		}
	}
	return nil
}

// ioctlNr constructs an AIX ioctl number from type byte, command, and size.
func ioctlNr(typ byte, nr uint32, size uint32) uint32 {
	return (uint32(typ) << 24) | (size << 8) | nr
}
