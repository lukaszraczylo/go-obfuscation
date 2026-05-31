//go:build windows

package antidebug

import (
	"syscall"
	"unsafe"
)

const _CONTEXT_DEBUG_REGISTERS = 0x00100010

type contextDebugRegs struct {
	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64
}

func checkHardwareBreakpoints() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentThread := kernel32.NewProc("GetCurrentThread")
	getThreadContext := kernel32.NewProc("GetThreadContext")

	thread, _, _ := getCurrentThread.Call()

	ctx := struct {
		contextFlags uint32
		_            [512]byte
		debugRegs    contextDebugRegs
	}{}
	ctx.contextFlags = _CONTEXT_DEBUG_REGISTERS

	ret, _, _ := getThreadContext.Call(
		thread,
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		return false
	}

	if ctx.debugRegs.Dr0 != 0 || ctx.debugRegs.Dr1 != 0 ||
		ctx.debugRegs.Dr2 != 0 || ctx.debugRegs.Dr3 != 0 {
		return true
	}

	if ctx.debugRegs.Dr7&0x55 != 0 {
		return true
	}

	return false
}
