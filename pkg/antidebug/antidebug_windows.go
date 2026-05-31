//go:build windows

package antidebug

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	ntdll                      = syscall.NewLazyDLL("ntdll.dll")
	procIsDebuggerPresent      = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger    = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProc = ntdll.NewProc("NtQueryInformationProcess")
	procNtSetInformationThread = ntdll.NewProc("NtSetInformationThread")
	procOutputDebugStringW     = kernel32.NewProc("OutputDebugStringW")
	procSetUnhandledException  = kernel32.NewProc("SetUnhandledExceptionFilter")
)

const (
	processDebugPort         = 7
	processDebugObjectHandle = 0x1E
	processDebugFlags        = 0x1F
	threadHideFromDebugger   = 0x11
)

func checkPtrace() error {
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return fmt.Errorf("antidebug: IsDebuggerPresent returned true")
	}

	var isRemoteDebugged int32
	currentProc, _ := syscall.GetCurrentProcess()
	ret, _, _ = procCheckRemoteDebugger.Call(
		uintptr(currentProc),
		uintptr(unsafe.Pointer(&isRemoteDebugged)),
	)
	if ret != 0 && isRemoteDebugged != 0 {
		return fmt.Errorf("antidebug: CheckRemoteDebuggerPresent detected debugger")
	}

	var port uint32
	var returnLength uint32
	ret, _, _ = procNtQueryInformationProc.Call(
		uintptr(currentProc),
		processDebugPort,
		uintptr(unsafe.Pointer(&port)),
		unsafe.Sizeof(port),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 && port != 0 {
		return fmt.Errorf("antidebug: NtQueryInformationProcess(ProcessDebugPort) detected debugger (port=%d)", port)
	}

	var debugHandle uintptr
	ret, _, _ = procNtQueryInformationProc.Call(
		uintptr(currentProc),
		processDebugObjectHandle,
		uintptr(unsafe.Pointer(&debugHandle)),
		unsafe.Sizeof(debugHandle),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return fmt.Errorf("antidebug: NtQueryInformationProcess(ProcessDebugObjectHandle) detected debugger")
	}

	var debugFlags uint32
	ret, _, _ = procNtQueryInformationProc.Call(
		uintptr(currentProc),
		processDebugFlags,
		uintptr(unsafe.Pointer(&debugFlags)),
		unsafe.Sizeof(debugFlags),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 && debugFlags == 0 {
		return fmt.Errorf("antidebug: NtQueryInformationProcess(ProcessDebugFlags) detected debugger")
	}

	return nil
}

func checkPEB() error {
	var pebBase uintptr
	var returnLength uint32
	currentProc, _ := syscall.GetCurrentProcess()

	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessID uintptr
		Reserved3       uintptr
	}

	var info processBasicInfo
	ret, _, _ := procNtQueryInformationProc.Call(
		uintptr(currentProc),
		0,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret != 0 {
		return nil
	}

	pebBase = info.PebBaseAddress
	if pebBase == 0 {
		return nil
	}

	beingDebugged := *(*byte)(unsafe.Pointer(pebBase + 2))
	if beingDebugged != 0 {
		return fmt.Errorf("antidebug: PEB.BeingDebugged is set")
	}

	ntGlobalFlag := *(*uint32)(unsafe.Pointer(pebBase + 0xBC))
	const FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
	const FLG_HEAP_ENABLE_FREE_CHECK = 0x20
	const FLG_HEAP_VALIDATE_PARAMETERS = 0x40
	debugFlags := FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
	if ntGlobalFlag&uint32(debugFlags) != 0 {
		return fmt.Errorf("antidebug: PEB.NtGlobalFlag has debug flags (0x%x)", ntGlobalFlag)
	}

	return nil
}

func checkHardwareBreakpoints() error {
	type context struct {
		ContextFlags      uint32
		Dr0               uintptr
		Dr1               uintptr
		Dr2               uintptr
		Dr3               uintptr
		Dr6               uintptr
		Dr7               uintptr
		FloatSave         [112]byte
		SegGs             uint32
		SegFs             uint32
		SegEs             uint32
		SegDs             uint32
		Edi               uintptr
		Esi               uintptr
		Ebx               uintptr
		Edx               uintptr
		Ecx               uintptr
		Eax               uintptr
		Ebp               uintptr
		Eip               uintptr
		SegCs             uint32
		EFlags            uint32
		Esp               uintptr
		SegSs             uint32
		ExtendedRegisters [512]byte
	}

	threadHandle, _ := syscall.GetCurrentThread()

	var ctx context
	ctx.ContextFlags = 0x00100010

	procGetThreadContext := kernel32.NewProc("GetThreadContext")
	ret, _, _ := procGetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		return nil
	}

	if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
		return fmt.Errorf("antidebug: hardware breakpoints detected (dr0=0x%x dr1=0x%x dr2=0x%x dr3=0x%x)",
			ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3)
	}

	return nil
}

func hideFromDebugger() {
	threadHandle, _ := syscall.GetCurrentThread()
	procNtSetInformationThread.Call(
		uintptr(threadHandle),
		threadHideFromDebugger,
		0,
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
		hideFromDebugger()
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
