package antiemul

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var platformCheck func() bool

func Check() bool {
	if checkTiming() {
		return true
	}
	if checkMemory() {
		return true
	}
	if checkUptime() {
		return true
	}
	if checkCoreCount() {
		return true
	}
	if platformCheck != nil && platformCheck() {
		return true
	}
	return false
}

func checkTiming() bool {
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		_ = i * i
	}
	return time.Since(start) > 500*time.Millisecond
}

func checkMemory() bool {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	content := string(data)
	idx := strings.Index(content, "MemTotal:")
	if idx == -1 {
		return false
	}
	rest := content[idx+9:]
	rest = strings.TrimSpace(rest)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return false
	}
	kb, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return false
	}
	return kb < 2000000
}

func checkUptime() bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false
	}
	content := strings.TrimSpace(string(data))
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return false
	}
	return seconds < 60.0
}

func checkCoreCount() bool {
	return runtime.NumCPU() < 2
}
