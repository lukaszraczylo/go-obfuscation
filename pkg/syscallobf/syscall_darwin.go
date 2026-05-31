//go:build darwin

package syscallobf

import (
	"crypto/rand"
	"syscall"
	"unsafe"
)

var (
	obfPtraceTrap   ObfuscatedCall
	obfGetpidTrap   ObfuscatedCall
	obfKillTrap     ObfuscatedCall
	obfOpenTrap     ObfuscatedCall
	obfCloseTrap    ObfuscatedCall
	obfReadTrap     ObfuscatedCall
	obfLseekTrap    ObfuscatedCall
	obfMmapTrap     ObfuscatedCall
	obfMprotectTrap ObfuscatedCall
)

func init() {
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic("syscallobf: failed to generate random key: " + err.Error())
	}

	obfPtraceTrap = encode(0x200001A, key)
	obfGetpidTrap = encode(0x2000027, key)
	obfKillTrap = encode(0x2000025, key)
	obfOpenTrap = encode(0x2000005, key)
	obfCloseTrap = encode(0x2000006, key)
	obfReadTrap = encode(0x2000003, key)
	obfLseekTrap = encode(0x20000C7, key)
	obfMmapTrap = encode(0x20000C5, key)
	obfMprotectTrap = encode(0x200004A, key)
}

func ObfPtrace(request int, pid uintptr, addr uintptr, data uintptr) (uintptr, uintptr, syscall.Errno) {
	trap := obfPtraceTrap.Num()
	r1, r2, errno := syscall.RawSyscall6(trap, uintptr(request), pid, addr, data, 0, 0)
	return r1, r2, errno
}

func ObfGetpid() int {
	trap := obfGetpidTrap.Num()
	r1, _, _ := syscall.RawSyscall(trap, 0, 0, 0)
	return int(r1)
}

func ObfKill(pid int, sig int) error {
	trap := obfKillTrap.Num()
	_, _, errno := syscall.RawSyscall(trap, uintptr(pid), uintptr(sig), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ObfOpen(path string, flags int, mode int) (int, error) {
	trap := obfOpenTrap.Num()
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	r1, _, errno := syscall.RawSyscall(trap, uintptr(unsafe.Pointer(pathBytes)), uintptr(flags), uintptr(mode))
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

func ObfClose(fd int) error {
	trap := obfCloseTrap.Num()
	_, _, errno := syscall.RawSyscall(trap, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ObfRead(fd int, buf []byte) (int, error) {
	trap := obfReadTrap.Num()
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	r1, _, errno := syscall.RawSyscall(trap, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(len(buf)))
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

func ObfLseek(fd int, offset int64, whence int) (int64, error) {
	trap := obfLseekTrap.Num()
	r1, _, errno := syscall.RawSyscall(trap, uintptr(fd), uintptr(offset), uintptr(whence))
	if errno != 0 {
		return int64(r1), errno
	}
	return int64(r1), nil
}

func ObfMmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset uintptr) (uintptr, error) {
	trap := obfMmapTrap.Num()
	r1, _, errno := syscall.Syscall6(trap, addr, length, uintptr(prot), uintptr(flags), uintptr(fd), offset)
	if errno != 0 {
		return 0, errno
	}
	return r1, nil
}

func ObfMprotect(addr uintptr, length uintptr, prot int) error {
	trap := obfMprotectTrap.Num()
	_, _, errno := syscall.RawSyscall(trap, addr, length, uintptr(prot))
	if errno != 0 {
		return errno
	}
	return nil
}
