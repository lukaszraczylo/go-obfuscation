//go:build linux

package antiemul

import (
	"os"
	"strings"
)

func init() {
	platformCheck = func() bool {
		if checkCPUInfo() {
			return true
		}
		if checkDMI() {
			return true
		}
		return false
	}
}

func checkCPUInfo() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	content := strings.ToUpper(string(data))
	signatures := []string{"QEMU", "VIRTUAL", "KVM"}
	for _, sig := range signatures {
		if strings.Contains(content, sig) {
			return true
		}
	}
	return false
}

func checkDMI() bool {
	data, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name")
	if err != nil {
		return false
	}
	product := strings.ToUpper(strings.TrimSpace(string(data)))
	vmStrings := []string{
		"QEMU", "VIRTUAL", "KVM", "VMWARE", "VBOX",
		"VIRTUALBOX", "XEN", "HYPER-V", "PARALLELS",
	}
	for _, vm := range vmStrings {
		if strings.Contains(product, vm) {
			return true
		}
	}
	return false
}
