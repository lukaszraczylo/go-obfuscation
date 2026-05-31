//go:build linux

package antidbi

import (
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var dbiSignatures = []string{
	"frida-agent",
	"frida-gadget",
	"dynamorio",
	"libdynamorio",
	"libpin",
}

var socketSignatures = []string{
	"frida",
	"linjector",
}

var threadSignatures = []string{
	"gmain",
	"frida",
}

var linuxEnvSignatures = []string{
	"frida",
	"dynamorio",
	"pin",
}

func readFileSyscall(path string) ([]byte, error) {
	pathBytes := append([]byte(path), 0)
	fd, _, errno := syscall.RawSyscall(
		uintptr(syscall.SYS_OPEN),
		uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(syscall.O_RDONLY),
		0,
	)
	if fd == ^uintptr(0) || fd >= 0x7fffffffffff {
		return nil, errno
	}
	defer syscall.Close(int(fd))

	buf := make([]byte, 64*1024)
	n, _, errno := syscall.RawSyscall(
		uintptr(syscall.SYS_READ),
		fd,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == ^uintptr(0) || n >= 0x7fffffffffff {
		return nil, errno
	}
	return buf[:n], nil
}

func checkMemoryMaps() bool {
	data, err := readFileSyscall("/proc/self/maps")
	if err != nil {
		return false
	}
	content := string(data)
	for _, sig := range dbiSignatures {
		if strings.Contains(content, sig) {
			return true
		}
	}
	return false
}

func checkUnixSockets() bool {
	data, err := readFileSyscall("/proc/net/unix")
	if err != nil {
		return false
	}
	content := string(data)
	for _, sig := range socketSignatures {
		if strings.Contains(content, sig) {
			return true
		}
	}
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
	data, err := readFileSyscall("/proc/self/task")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "." || line == ".." {
			continue
		}

		commPath := "/proc/self/task/" + line + "/comm"
		comm, err := readFileSyscall(commPath)
		if err != nil {
			continue
		}

		name := strings.TrimSpace(string(comm))
		for _, sig := range threadSignatures {
			if strings.Contains(name, sig) {
				return true
			}
		}
	}
	return false
}

func checkLoadedImages() bool {
	return false
}

func checkMachPorts() bool {
	return false
}

func checkEnvironment() bool {
	suspiciousVars := []string{
		"LD_PRELOAD",
		"FRIDA_DNS_SERVER",
		"_JAVA_OPTIONS",
	}

	for _, v := range suspiciousVars {
		val := strings.ToLower(os.Getenv(v))
		if val == "" {
			continue
		}
		for _, sig := range linuxEnvSignatures {
			if strings.Contains(val, sig) {
				return true
			}
		}
	}
	return false
}

func AntiAttach() {
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			if checkMemoryMaps() || checkUnixSockets() || checkFridaPort() || checkThreadNames() {
				syscall.Exit(66)
			}
		}
	}()
}
