//go:build darwin

package antidebug

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	ctlKern      = 1
	kernProc     = 14
	kernProcPID  = 1
	pTraced      = 0x00000800
	ptDenyAttach = 31
)

func checkPtrace() error {
	pid := os.Getpid()

	var mib [4]int32
	mib[0] = ctlKern
	mib[1] = kernProc
	mib[2] = kernProcPID
	mib[3] = int32(pid)

	bufSize := uintptr(64)
	buf := make([]byte, bufSize)

	_, _, errno := syscall.Syscall6(
		uintptr(0x2000000+202),
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		0,
	)

	if errno != 0 {
		return nil
	}

	if bufSize < 36 {
		return nil
	}

	pFlag := uint32(buf[32]) | uint32(buf[33])<<8 | uint32(buf[34])<<16 | uint32(buf[35])<<24

	if pFlag&pTraced != 0 {
		return fmt.Errorf("antidebug: debugger detected via sysctl P_TRACED (pid=%d)", pid)
	}

	return nil
}

func denyPtraceAttach() {
	pid := os.Getpid()
	syscall.RawSyscall(
		uintptr(syscall.SYS_PTRACE),
		uintptr(ptDenyAttach),
		uintptr(pid),
		0,
	)
}

func disableCoreDump() error {
	return nil
}

func checkTiming() error {
	start := time.Now()
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		return fmt.Errorf("antidebug: timing anomaly detected (%v for 1M iterations)", elapsed)
	}

	_ = sum
	return nil
}

func checkEnv() error {
	suspiciousVars := []string{
		"DYLD_INSERT_LIBRARIES",
		"DYLD_FRAMEWORK_PATH",
		"DYLD_LIBRARY_PATH",
		"DYLD_FALLBACK_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH",
		"DYLD_ROOT_PATH",
		"GODEBUG",
		"DELVE_LISTENER",
		"DEBUGINFOD_URL",
		"RR_LOG_FILE",
		"_JAVA_OPTIONS",
	}

	for _, v := range suspiciousVars {
		if os.Getenv(v) != "" {
			return fmt.Errorf("antidebug: suspicious env var %s=%s", v, os.Getenv(v))
		}
	}
	return nil
}

func checkParentProcess() error {
	return nil
}

func AntiAttach() {
	go func() {
		denyPtraceAttach()
		for {
			time.Sleep(500 * time.Millisecond)
			if err := checkPtrace(); err != nil {
				os.Exit(66)
			}
		}
	}()
}

func AntiDump() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_ = disableCoreDump()
		}
	}()
}

func CheckHooks() error {
	if err := checkFunctionPrologues(); err != nil {
		return err
	}
	if err := scanForBreakpoints(); err != nil {
		return err
	}
	return nil
}
