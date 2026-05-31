package antidebug

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

var suspiciousPatterns = []string{
	"frida", "dynamorio", "pin", "hook", "inject",
	"intercept", "instrument", "ltrace", "strace",
}

func checkReturnAddresses() bool {
	var pcs [16]uintptr
	n := runtime.Callers(2, pcs[:])
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		fn := runtime.FuncForPC(pcs[i])
		if fn == nil {
			return true
		}
		name := strings.ToLower(fn.Name())
		for _, pat := range suspiciousPatterns {
			if strings.Contains(name, pat) {
				return true
			}
		}
	}

	if !checkPCInBinary(pcs[0]) {
		return true
	}

	return false
}

func checkPCInBinary(pc uintptr) bool {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return false
	}
	defer f.Close()

	selfPath, _ := os.Executable()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "r-xp") && !strings.Contains(line, "r--p") {
			continue
		}
		if selfPath != "" && !strings.Contains(line, selfPath) {
			continue
		}

		var start, end uintptr
		if _, err := fmt.Sscanf(line, "%x-%x", &start, &end); err != nil {
			continue
		}
		if pc >= start && pc < end {
			return true
		}
	}
	return false
}
