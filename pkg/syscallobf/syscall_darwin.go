package syscallobf

import "syscall"

func ObfPtrace(request int, pid uintptr, addr uintptr, data uintptr) (uintptr, uintptr, syscall.Errno) {
	return 0, 0, syscall.ENOSYS
}

func ObfGetpid() int {
	return 0
}

func ObfKill(pid int, sig int) error {
	return syscall.ENOSYS
}

func ObfOpen(path string, flags int, mode int) (int, error) {
	return -1, syscall.ENOSYS
}

func ObfClose(fd int) error {
	return syscall.ENOSYS
}

func ObfRead(fd int, buf []byte) (int, error) {
	return 0, syscall.ENOSYS
}

func ObfMmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset uintptr) (uintptr, error) {
	return 0, syscall.ENOSYS
}

func ObfMprotect(addr uintptr, length uintptr, prot int) error {
	return syscall.ENOSYS
}

func ObfLseek(fd int, offset int64, whence int) (int64, error) {
	return 0, syscall.ENOSYS
}
