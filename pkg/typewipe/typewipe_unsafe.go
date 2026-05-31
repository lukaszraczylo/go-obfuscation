//go:build darwin || linux

package typewipe

import (
	"syscall"
	"unsafe"
)

//go:nosplit
func mprotectRW(addr uintptr, size uintptr) error {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return syscall.Mprotect(
		unsafe.Slice((*byte)(p), size),
		syscall.PROT_READ|syscall.PROT_WRITE,
	)
}

//go:nosplit
func mprotectRO(addr uintptr, size uintptr) error {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return syscall.Mprotect(
		unsafe.Slice((*byte)(p), size),
		syscall.PROT_READ,
	)
}

//go:nosplit
func ptrToSlice(addr uintptr, size uintptr) []byte {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(p), size)
}
