package antidbi

import (
	"os"
	"strings"
)

var fridaMemorySignatures = []string{
	"frida-agent",
	"gmain",
	"gum-js-loop",
	"linjector",
	"frida-gadget",
	"frida:rpc",
	"frida-agent-64.so",
	"frida-agent-32.so",
}

var fridaPipeSignatures = []string{
	"frida-",
	"linjector-",
	"gum-",
}

var fridaThreadSignatures = []string{
	"gmain",
	"gdbus",
	"gum-js-loop",
	"linjector",
}

func ScanMemoryMapsForFrida() bool {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false
	}
	content := string(data)
	for _, sig := range fridaMemorySignatures {
		if strings.Contains(content, sig) {
			return true
		}
	}
	return false
}

func ScanNamedPipesForFrida() bool {
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		for _, sig := range fridaPipeSignatures {
			if strings.HasPrefix(name, sig) {
				return true
			}
		}
	}
	return false
}

func ScanThreadsForFrida() bool {
	taskDir, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return false
	}
	for _, entry := range taskDir {
		if !entry.IsDir() {
			continue
		}
		commPath := "/proc/self/task/" + entry.Name() + "/comm"
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		for _, sig := range fridaThreadSignatures {
			if strings.Contains(name, sig) {
				return true
			}
		}
	}
	return false
}
