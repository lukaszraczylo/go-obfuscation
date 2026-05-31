package antidebug

import (
	"syscall"
	"unsafe"
)

const (
	offsetofDR0 = 6 * 8  // offsetof(struct user, u_debugreg[0])
	offsetofDR7 = 13 * 8 // offsetof(struct user, u_debugreg[7])
)

func checkHardwareBreakpoints() bool {
	pid, _, _ := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)

	if pid == 0 {
		// Child: attach to parent, read debug registers, report via exit code
		syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_ATTACH), uintptr(syscall.Getppid()), 0)
		var status syscall.WaitStatus
		syscall.RawSyscall(syscall.SYS_WAIT4, uintptr(syscall.Getppid()), uintptr(unsafe.Pointer(&status)), 0, 0)

		detected := false
		for i := 0; i < 4; i++ {
			drVal, _, _ := syscall.RawSyscall6(
				syscall.SYS_PTRACE,
				uintptr(syscall.PTRACE_PEEKUSER),
				uintptr(syscall.Getppid()),
				uintptr(offsetofDR0+i*8),
				0, 0, 0,
			)
			if drVal != 0 {
				detected = true
				break
			}
		}

		if !detected {
			dr7, _, _ := syscall.RawSyscall6(
				syscall.SYS_PTRACE,
				uintptr(syscall.PTRACE_PEEKUSER),
				uintptr(syscall.Getppid()),
				uintptr(offsetofDR7),
				0, 0, 0,
			)
			// Bits 0,2,4,6 enable DR0-DR3; bits 1,3,5,7 are condition bits
			// If any enable bit is set, a hardware breakpoint is active
			if dr7&0x55 != 0 {
				detected = true
			}
		}

		syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_DETACH), uintptr(syscall.Getppid()), 0)

		exitCode := 0
		if detected {
			exitCode = 1
		}
		syscall.RawSyscall(syscall.SYS_EXIT, uintptr(exitCode), 0, 0)
	}

	// Parent: wait for child result
	var status syscall.WaitStatus
	syscall.RawSyscall(syscall.SYS_WAIT4, pid, uintptr(unsafe.Pointer(&status)), 0, 0)
	return status.ExitStatus() == 1
}
