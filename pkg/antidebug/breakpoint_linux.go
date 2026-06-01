//go:build linux

package antidebug

import (
	"fmt"
	"syscall"
	"unsafe"
)

func CheckHardwareBreakpoints() (bool, error) {
	const ptraceGetRegs = 12
	pid := 0
	var regs syscall.PtraceRegs
	_, _, e := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(ptraceGetRegs), uintptr(pid), 0, uintptr(unsafe.Pointer(&regs)), 0, 0)
	if e != 0 {
		return false, fmt.Errorf("antidebug: ptrace GETREGS failed: %v", e)
	}
	if regs.Debugreg0 != 0 || regs.Debugreg1 != 0 || regs.Debugreg2 != 0 || regs.Debugreg3 != 0 {
		return true, nil
	}
	return false, nil
}
