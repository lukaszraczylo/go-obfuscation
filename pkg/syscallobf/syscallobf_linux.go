//go:build linux

package syscallobf

import (
	"crypto/rand"
	"runtime"
	"syscall"
	"unsafe"
)

var key [4]byte

var (
	obfOpenat   ObfuscatedCall
	obfRead     ObfuscatedCall
	obfWrite    ObfuscatedCall
	obfClose    ObfuscatedCall
	obfMprotect ObfuscatedCall
)

func init() {
	if _, err := rand.Read(key[:]); err != nil {
		panic("syscallobf: failed to generate random key: " + err.Error())
	}

	if runtime.GOARCH == "arm64" {
		obfOpenat = encode(56, key)
		obfRead = encode(63, key)
		obfWrite = encode(64, key)
		obfClose = encode(57, key)
		obfMprotect = encode(226, key)
	} else {
		obfOpenat = encode(257, key)
		obfRead = encode(0, key)
		obfWrite = encode(1, key)
		obfClose = encode(3, key)
		obfMprotect = encode(10, key)
	}
}

//go:nosplit
func OpenFile(path string, flags int, mode uint32) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	r1, _, errno := syscall.Syscall(
		obfOpenat.Num(),
		uintptr(syscall.AT_FDCWD),
		uintptr(unsafe.Pointer(p)),
		uintptr(flags)|uintptr(mode),
	)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

//go:nosplit
func SysRead(fd int, buf []byte) (int, error) {
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	r1, _, errno := syscall.Syscall(
		obfRead.Num(),
		uintptr(fd),
		uintptr(unsafe.Pointer(p)),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

//go:nosplit
func SysWrite(fd int, buf []byte) (int, error) {
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	r1, _, errno := syscall.Syscall(
		obfWrite.Num(),
		uintptr(fd),
		uintptr(unsafe.Pointer(p)),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

//go:nosplit
func SysClose(fd int) error {
	_, _, errno := syscall.Syscall(
		obfClose.Num(),
		uintptr(fd),
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

//go:nosplit
func SysMprotect(addr uintptr, length int, prot int) error {
	_, _, errno := syscall.Syscall(
		obfMprotect.Num(),
		addr,
		uintptr(length),
		uintptr(prot),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
