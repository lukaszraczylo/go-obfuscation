//go:build linux

package antidebug

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"

	"github.com/self-evolving-research/obfuscator/pkg/syscallobf"
)

func checkFunctionPrologues() error {
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

		prologue, err := readProcMemory(t.addr, t.addr+8)
		if err != nil || len(prologue) < 2 {
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
	mapsData, err := readProcFile("/proc/self/maps")
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(mapsData)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		if !strings.Contains(parts[1], "x") {
			continue
		}

		if len(parts) >= 6 && strings.HasPrefix(parts[5], "[") {
			continue
		}

		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		var start, end uintptr
		fmt.Sscanf(addrRange[0], "%x", &start)
		fmt.Sscanf(addrRange[1], "%x", &end)

		if end <= start || end-start > 50*1024*1024 {
			continue
		}

		mem, err := readProcMemory(start, end)
		if err != nil || len(mem) == 0 {
			continue
		}

		maxConsecutive := 0
		consecutive := 0
		for _, b := range mem {
			if b == 0xCC {
				consecutive++
				if consecutive > maxConsecutive {
					maxConsecutive = consecutive
				}
			} else {
				consecutive = 0
			}
		}

		if maxConsecutive >= 8 {
			return fmt.Errorf("antidebug: breakpoint cluster (%d consecutive INT3) at 0x%x-0x%x", maxConsecutive, start, end)
		}
	}

	return nil
}

func readProcFile(path string) ([]byte, error) {
	fd, err := syscallobf.ObfOpen(path, 0, 0)
	if fd < 0 {
		return nil, err
	}
	defer syscallobf.ObfClose(fd)

	var result []byte
	buf := make([]byte, 4096)
	for {
		n, readErr := syscallobf.ObfRead(fd, buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	return result, nil
}

func readProcMemory(start, end uintptr) ([]byte, error) {
	fd, err := syscallobf.ObfOpen("/proc/self/mem", 0, 0)
	if fd < 0 {
		return nil, err
	}
	defer syscallobf.ObfClose(fd)

	size := int(end - start)
	if size <= 0 || size > 50*1024*1024 {
		return nil, fmt.Errorf("invalid region size")
	}

	buf := make([]byte, size)

	if _, seekErr := syscallobf.ObfLseek(fd, int64(start), 0); seekErr != nil {
		return nil, seekErr
	}

	totalRead := 0
	for totalRead < size {
		n, readErr := syscallobf.ObfRead(fd, buf[totalRead:])
		if n > 0 {
			totalRead += n
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	return buf[:totalRead], nil
}
