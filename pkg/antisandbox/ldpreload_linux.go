//go:build linux

package antisandbox

import (
	"bufio"
	"os"
	"strings"
)

var suspiciousLibPaths = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
	"/home/",
	"/root/",
}

func CheckLDPreload() bool {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		idx := strings.Index(line, "/")
		if idx < 0 {
			continue
		}
		path := line[idx:]
		if !strings.HasSuffix(path, ".so") && !strings.Contains(path, ".so.") {
			continue
		}
		for _, sus := range suspiciousLibPaths {
			if strings.HasPrefix(path, sus) {
				return true
			}
		}
	}
	return false
}

func CheckLdSoPreload() bool {
	f, err := os.Open("/etc/ld.so.preload")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			return true
		}
	}
	return false
}

func UnsetInjectedEnv() error {
	if err := os.Unsetenv("LD_PRELOAD"); err != nil {
		return err
	}
	if err := os.Unsetenv("LD_LIBRARY_PATH"); err != nil {
		return err
	}
	return nil
}
