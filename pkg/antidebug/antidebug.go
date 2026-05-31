package antidebug

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

func Check() error {
	if runtime.GOOS == "linux" {
		if err := checkPtrace(); err != nil {
			return err
		}
		if err := disableCoreDump(); err != nil {
			return err
		}
	}

	if err := checkTiming(); err != nil {
		return err
	}

	if err := checkEnv(); err != nil {
		return err
	}

	if err := checkParentProcess(); err != nil {
		return err
	}

	if err := CheckHooks(); err != nil {
		return err
	}

	return nil
}

func checkPtrace() error {
	self, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}

	data := string(self)
	for i := 0; i < len(data)-11; i++ {
		if data[i:i+11] == "TracerPid:\t" {
			j := i + 11
			for j < len(data) && data[j] >= '0' && data[j] <= '9' {
				j++
			}
			pid := data[i+11 : j]
			if pid != "0" {
				return fmt.Errorf("antidebug: debugger detected (tracer pid=%s)", pid)
			}
			break
		}
	}
	return nil
}

func disableCoreDump() error {
	f, err := os.OpenFile("/proc/self/coredump_filter", os.O_WRONLY, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	_, _ = f.WriteString("0")
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
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
	}

	for _, v := range suspiciousVars {
		if os.Getenv(v) != "" {
			return fmt.Errorf("antidebug: suspicious env var %s=%s", v, os.Getenv(v))
		}
	}
	return nil
}

func checkParentProcess() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	ppid := os.Getppid()
	if ppid <= 1 {
		return nil
	}

	commPath := fmt.Sprintf("/proc/%d/comm", ppid)
	comm, err := os.ReadFile(commPath)
	if err != nil {
		return nil
	}

	parent := string(comm)
	debuggers := []string{
		"gdb", "lldb", "strace", "ltrace", "ida", "ida64",
		"radare2", "r2", "ghidra", "x64dbg", "ollydbg",
		"delve", "debugserver",
	}

	for _, d := range debuggers {
		if len(parent) >= len(d) && parent[:len(d)] == d {
			return fmt.Errorf("antidebug: parent process is debugger: %s", parent)
		}
	}
	return nil
}

func AntiAttach() {
	if runtime.GOOS != "linux" {
		return
	}
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			if err := checkPtrace(); err != nil {
				os.Exit(66)
			}
		}
	}()
}

func AntiDump() {
	if runtime.GOOS != "linux" {
		return
	}
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
