//go:build windows

package antiemul

import (
	"syscall"
	"unsafe"
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func init() {
	platformCheck = func() bool {
		if checkTiming() {
			return true
		}
		if checkWindowsMemory() {
			return true
		}
		return false
	}
}

func checkWindowsMemory() bool {
	mod := syscall.NewLazyDLL("kernel32.dll")
	proc := mod.NewProc("GlobalMemoryStatusEx")
	var memStatus memoryStatusEx
	memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
	r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&memStatus)))
	if r1 == 0 {
		return false
	}
	return memStatus.ullTotalPhys < 2*1024*1024*1024
}
