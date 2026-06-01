//go:build darwin

package antidebug

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

func checkFunctionPrologues() error {
	type target struct {
		name string
		addr uintptr
	}

	targets := []target{
		{"os.Exit", reflect.ValueOf(os.Exit).Pointer()},
		{"runtime.Goexit", reflect.ValueOf(runtime.Goexit).Pointer()},
	}

	for _, t := range targets {
		if t.addr == 0 {
			continue
		}

		prologue := readAddr(t.addr, 8)
		if len(prologue) < 2 {
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

		if runtime.GOARCH == "arm64" {
			instr := uint32(prologue[0]) | uint32(prologue[1])<<8 | uint32(prologue[2])<<16 | uint32(prologue[3])<<24
			if instr&0xFC000000 == 0x14000000 {
				return fmt.Errorf("antidebug: ARM64 B hook detected at %s (0x%x)", t.name, t.addr)
			}
			if instr&0xFFE0001F == 0xD61F0000 {
				return fmt.Errorf("antidebug: ARM64 BR hook detected at %s (0x%x)", t.name, t.addr)
			}
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

	for _, t := range targets {
		if t.addr == 0 {
			continue
		}

		region := readAddr(t.addr, 64)
		if len(region) < 8 {
			continue
		}

		maxConsecutive := 0
		consecutive := 0
		for _, b := range region {
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

func readAddr(addr uintptr, size int) []byte {
	if size <= 0 || size > 4096 {
		return nil
	}
	buf := make([]byte, size)
	a := addr
	src := unsafe.Slice((*byte)(unsafe.Pointer(a^0)), size)
	copy(buf, src)
	return buf
}
