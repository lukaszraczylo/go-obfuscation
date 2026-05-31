package syscallobf

import (
	"syscall"
	"unsafe"
)

var (
	encPtraceTrap   = NewEncodedSyscall(101)
	encGetpidTrap   = NewEncodedSyscall(39)
	encKillTrap     = NewEncodedSyscall(62)
	encOpenTrap     = NewEncodedSyscall(2)
	encCloseTrap    = NewEncodedSyscall(3)
	encReadTrap     = NewEncodedSyscall(0)
	encMmapTrap     = NewEncodedSyscall(9)
	encMprotectTrap = NewEncodedSyscall(10)
	encLseekTrap    = NewEncodedSyscall(8)
)

func ObfPtrace(request int, pid uintptr, addr uintptr, data uintptr) (uintptr, uintptr, syscall.Errno) {
	trap := encPtraceTrap.Trap()
	return syscall.RawSyscall6(trap, uintptr(request), pid, addr, data, 0, 0)
}

func ObfGetpid() int {
	trap := encGetpidTrap.Trap()
	r1, _, _ := syscall.RawSyscall(trap, 0, 0, 0)
	return int(r1)
}

func ObfKill(pid int, sig int) error {
	trap := encKillTrap.Trap()
	_, _, errno := syscall.RawSyscall(trap, uintptr(pid), uintptr(sig), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ObfOpen(path string, flags int, mode int) (int, error) {
	trap := encOpenTrap.Trap()
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
	trap := encCloseTrap.Trap()
	_, _, errno := syscall.RawSyscall(trap, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ObfRead(fd int, buf []byte) (int, error) {
	trap := encReadTrap.Trap()
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

func ObfMmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset uintptr) (uintptr, error) {
	trap := encMmapTrap.Trap()
	r1, _, errno := syscall.Syscall6(trap, addr, length, uintptr(prot), uintptr(flags), uintptr(fd), offset)
	if errno != 0 {
		return 0, errno
	}
	return r1, nil
}

func ObfMprotect(addr uintptr, length uintptr, prot int) error {
	trap := encMprotectTrap.Trap()
	_, _, errno := syscall.RawSyscall(trap, addr, length, uintptr(prot))
	if errno != 0 {
		return errno
	}
	return nil
}

func ObfLseek(fd int, offset int64, whence int) (int64, error) {
	trap := encLseekTrap.Trap()
	r1, _, errno := syscall.RawSyscall(trap, uintptr(fd), uintptr(offset), uintptr(whence))
	if errno != 0 {
		return int64(r1), errno
	}
	return int64(r1), nil
}
