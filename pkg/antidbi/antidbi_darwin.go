//go:build darwin

package antidbi

import (
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var dylibSignatures = []string{
	"frida-agent",
	"frida-gadget",
	"frida-tracer",
}

var dylibSearchPaths = []string{
	"/usr/local/lib/",
	"/usr/lib/",
	"/Library/Frameworks/",
}

var machPortSignatures = []string{
	"re.frida.server",
	"re.frida.agent",
	"linjector",
}

var darwinEnvSignatures = []string{
	"frida",
	"frida-agent",
	"frida-gadget",
}

func checkMemoryMaps() bool {
	return false
}

func checkUnixSockets() bool {
	return false
}

func checkFridaPort() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:27042", 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkThreadNames() bool {
	return false
}

func checkLoadedImages() bool {
	dyld := os.Getenv("DYLD_INSERT_LIBRARIES")
	if dyld != "" {
		lower := strings.ToLower(dyld)
		for _, sig := range dylibSignatures {
			if strings.Contains(lower, sig) {
				return true
			}
		}
	}

	for _, dir := range dylibSearchPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			for _, sig := range dylibSignatures {
				if strings.Contains(name, sig) {
					return true
				}
			}
		}
	}

	return false
}

func checkMachPorts() bool {
	taskSelf := machTaskSelf()
	if taskSelf == 0 {
		return false
	}

	var bootstrapPort uint32
	ret, _, _ := syscall.Syscall(
		uintptr(0x1000000+45),
		uintptr(taskSelf),
		uintptr(unsafe.Pointer(&bootstrapPort)),
		0,
	)
	if ret != 0 || bootstrapPort == 0 {
		return false
	}

	for _, portName := range machPortSignatures {
		cname := append([]byte(portName), 0)
		var port uint32
		ret, _, _ := syscall.Syscall(
			uintptr(0x2000000+410),
			uintptr(unsafe.Pointer(&cname[0])),
			uintptr(unsafe.Pointer(&port)),
			0,
		)
		if ret == 0 && port != 0 {
			return true
		}
	}

	return false
}

func checkEnvironment() bool {
	envVars := []string{
		"DYLD_INSERT_LIBRARIES",
		"DYLD_FRAMEWORK_PATH",
		"DYLD_LIBRARY_PATH",
		"DYLD_FALLBACK_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH",
	}

	for _, v := range envVars {
		val := os.Getenv(v)
		if val == "" {
			continue
		}
		lower := strings.ToLower(val)
		for _, sig := range darwinEnvSignatures {
			if strings.Contains(lower, sig) {
				return true
			}
		}
	}

	return false
}

func machTaskSelf() uint32 {
	ret, _, _ := syscall.Syscall(
		uintptr(0x1000000+28),
		0,
		0,
		0,
	)
	return uint32(ret)
}

func AntiAttach() {
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			if checkLoadedImages() || checkMachPorts() || checkEnvironment() || checkFridaPort() {
				syscall.Exit(66)
			}
		}
	}()
}
