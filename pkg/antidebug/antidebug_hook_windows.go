//go:build windows

package antidebug

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"
)

var procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")

func checkFunctionPrologues() error {
	type target struct {
		name string
		addr uintptr
	}

	targets := []target{
		{"os.Exit", reflect.ValueOf(os.Exit).Pointer()},
		{"runtime.Goexit", reflect.ValueOf(runtime.Goexit).Pointer()},
	}

	currentProc, _ := syscall.GetCurrentProcess()

	for _, t := range targets {
		if t.addr == 0 {
			continue
		}

		prologue := make([]byte, 8)
		var bytesRead uintptr
		ret, _, _ := procReadProcessMemory.Call(
			uintptr(currentProc),
			t.addr,
			uintptr(unsafe.Pointer(&prologue[0])),
			uintptr(len(prologue)),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 || bytesRead < 2 {
			continue
		}

		if prologue[0] == 0xE9 {
			return fmt.Errorf("antidebug: JMP hook detected at %s (0x%x)", t.name, t.addr)
		}
		if prologue[0] == 0xEB {
			return fmt.Errorf("antidebug: short JMP hook detected at %s (0x%x)", t.name, t.addr)
		}
		if prologue[0] == 0xFF && prologue[1] == 0x25 {
			return fmt.Errorf("antidebug: indirect JMP hook detected at %s (0x%x)", t.name, t.addr)
		}
		if prologue[0] == 0xCC && prologue[1] == 0xCC {
			return fmt.Errorf("antidebug: INT3 breakpoint at %s (0x%x)", t.name, t.addr)
		}
	}

	return nil
}

func scanForBreakpoints() error {
	type target struct {
		name string
		addr uintptr
	}

	targets := []target{
		{"os.Exit", reflect.ValueOf(os.Exit).Pointer()},
		{"runtime.Goexit", reflect.ValueOf(runtime.Goexit).Pointer()},
		{"fmt.Printf", reflect.ValueOf(fmt.Printf).Pointer()},
		{"os.ReadFile", reflect.ValueOf(os.ReadFile).Pointer()},
	}

	currentProc, _ := syscall.GetCurrentProcess()

	for _, t := range targets {
		if t.addr == 0 {
			continue
		}

		region := make([]byte, 64)
		var bytesRead uintptr
		ret, _, _ := procReadProcessMemory.Call(
			uintptr(currentProc),
			t.addr,
			uintptr(unsafe.Pointer(&region[0])),
			uintptr(len(region)),
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if ret == 0 || bytesRead < 8 {
			continue
		}

		maxConsecutive := 0
		consecutive := 0
		for _, b := range region[:bytesRead] {
			if b == 0xCC {
				consecutive++
				if consecutive > maxConsecutive {
					maxConsecutive = consecutive
				}
			} else {
				consecutive = 0
			}
		}

		if maxConsecutive >= 4 {
			return fmt.Errorf("antidebug: breakpoint cluster (%d consecutive INT3) near %s at 0x%x", maxConsecutive, t.name, t.addr)
		}
	}

	return nil
}
