//go:build windows

package syscallobf

import (
	"crypto/rand"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modntdll = syscall.NewLazyDLL("ntdll.dll")

	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
	procNtSetInformationThread    = modntdll.NewProc("NtSetInformationThread")
	procNtClose                   = modntdll.NewProc("NtClose")
	procNtProtectVirtualMemory    = modntdll.NewProc("NtProtectVirtualMemory")
	procNtReadVirtualMemory       = modntdll.NewProc("NtReadVirtualMemory")
	procNtOpenProcess             = modntdll.NewProc("NtOpenProcess")

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

	obfCloseTrap = encode(0, key)
	obfReadTrap = encode(0, key)
	obfOpenTrap = encode(0, key)
	obfLseekTrap = encode(0, key)
	obfMmapTrap = encode(0, key)
	obfMprotectTrap = encode(0, key)
	obfPtraceTrap = encode(0, key)
	obfGetpidTrap = encode(0, key)
	obfKillTrap = encode(0, key)
}

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentPID  = kernel32.NewProc("GetCurrentProcessId")
	procOpenProcess    = kernel32.NewProc("OpenProcess")
	procCloseHandle    = kernel32.NewProc("CloseHandle")
	procReadProcessMem = kernel32.NewProc("ReadProcessMemory")
)

func ObfGetpid() int {
	r1, _, _ := procGetCurrentPID.Call()
	return int(r1)
}

func ObfOpen(path string, flags int, mode int) (int, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return -1, err
	}
	access := uint32(syscall.GENERIC_READ)
	if flags&syscall.O_WRONLY != 0 {
		access = syscall.GENERIC_WRITE
	}
	if flags&syscall.O_RDWR != 0 {
		access = syscall.GENERIC_READ | syscall.GENERIC_WRITE
	}
	creation := uint32(syscall.OPEN_EXISTING)
	if flags&syscall.O_CREAT != 0 {
		creation = syscall.CREATE_ALWAYS
	}
	h, _, err := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ, nil, creation, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil && err.(syscall.Errno) != 0 {
		return -1, err
	}
	return int(h), nil
}

func ObfClose(fd int) error {
	r1, _, err := procCloseHandle.Call(uintptr(fd))
	if r1 == 0 {
		return err
	}
	return nil
}

func ObfRead(fd int, buf []byte) (int, error) {
	var bytesRead uint32
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	r1, _, err := syscall.ReadFile(
		syscall.Handle(fd),
		buf,
		&bytesRead,
		nil,
	)
	if r1 == 0 {
		return int(bytesRead), err
	}
	return int(bytesRead), nil
}

func ObfLseek(fd int, offset int64, whence int) (int64, error) {
	var newOff int64
	high := int32(offset >> 32)
	r1, _, err := syscall.Seek(syscall.Handle(fd), int32(offset), high)
	if r1 == 0xffffffff && err != nil {
		return 0, err
	}
	_ = newOff
	return int64(r1), nil
}

func ObfMmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset uintptr) (uintptr, error) {
	flProtect := uint32(syscall.PAGE_READWRITE)
	if prot&syscall.PROT_EXEC != 0 {
		flProtect = syscall.PAGE_EXECUTE_READWRITE
	}
	h, _, err := syscall.CreateFileMapping(
		syscall.Handle(fd),
		nil,
		flProtect,
		uint32(length>>32),
		uint32(length),
		nil,
	)
	if h == 0 {
		return 0, err
	}
	return uintptr(h), nil
}

func ObfMprotect(addr uintptr, length uintptr, prot int) error {
	var oldProtect uint32
	flProtect := uint32(syscall.PAGE_READWRITE)
	if prot&syscall.PROT_EXEC != 0 {
		flProtect = syscall.PAGE_EXECUTE_READWRITE
	}
	r1, _, err := procNtProtectVirtualMemory.Call(
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&length)),
		uintptr(flProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r1 != 0 {
		return err
	}
	return nil
}

type windowsObfCall struct {
	once     sync.Once
	procAddr uintptr
	proc     *syscall.LazyProc
}

func (w *windowsObfCall) Call(args ...uintptr) (uintptr, uintptr, error) {
	w.once.Do(func() {
		if w.proc != nil {
			w.procAddr = w.proc.Addr()
		}
	})
	return syscall.Syscall(w.procAddr, uintptr(len(args)), args[0], args[1], args[2])
}

func NtQueryInformationProcess(handle uintptr, infoclass uint32, info uintptr, infolen uint32, retlen *uint32) uintptr {
	r1, _, _ := procNtQueryInformationProcess.Call(
		handle,
		uintptr(infoclass),
		info,
		uintptr(infolen),
		uintptr(unsafe.Pointer(retlen)),
	)
	return r1
}

func NtSetInformationThread(handle uintptr, infoclass uint32, info uintptr, infolen uint32) uintptr {
	r1, _, _ := procNtSetInformationThread.Call(
		handle,
		uintptr(infoclass),
		info,
		uintptr(infolen),
	)
	return r1
}
