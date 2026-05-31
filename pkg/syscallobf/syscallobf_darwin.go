//go:build darwin

package syscallobf

import (
	"syscall"
	"unsafe"
)

func OpenFile(path string, flags int, mode uint32) (int, error) {
	return syscall.Open(path, flags, mode)
}

func SysRead(fd int, buf []byte) (int, error) {
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	n, _, errno := syscall.Syscall(
		uintptr(syscall.SYS_READ),
		uintptr(fd),
		uintptr(unsafe.Pointer(p)),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func SysWrite(fd int, buf []byte) (int, error) {
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	n, _, errno := syscall.Syscall(
		uintptr(syscall.SYS_WRITE),
		uintptr(fd),
		uintptr(unsafe.Pointer(p)),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func SysClose(fd int) error {
	return syscall.Close(fd)
}

func SysMprotect(addr uintptr, length int, prot int) error {
	_, _, errno := syscall.Syscall(
		uintptr(syscall.SYS_MPROTECT),
		addr,
		uintptr(length),
		uintptr(prot),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
