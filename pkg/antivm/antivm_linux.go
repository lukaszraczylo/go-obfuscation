//go:build linux

package antivm

import (
	"net"
	"os"
	"strings"
	"time"
)

var vmIdentifiers = []string{
	"VMware",
	"VirtualBox",
	"QEMU",
	"KVM",
	"Xen",
	"Microsoft Corporation",
	"Parallels",
}

var vmMACPrefixes = []string{
	"00:0c:29",
	"08:00:27",
	"52:54:00",
	"00:1c:42",
}

var vmPCIVendors = []string{
	"15ad",
	"80ee",
	"1234",
}

func readSysfsTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func checkDMI() bool {
	paths := []string{
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_name",
	}
	for _, p := range paths {
		val := readSysfsTrimmed(p)
		if containsAny(val, vmIdentifiers) {
			return true
		}
	}
	return false
}

func checkMAC() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		if mac == "" {
			continue
		}
		for _, prefix := range vmMACPrefixes {
			if strings.HasPrefix(mac, prefix) {
				return true
			}
		}
	}
	return false
}

func checkCPUID() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	content := string(data)

	if strings.Contains(content, "hypervisor") {
		return true
	}

	if strings.Contains(content, "QEMU Virtual CPU") {
		return true
	}

	return false
}

func checkDisk() bool {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		modelPath := "/sys/block/" + entry.Name() + "/device/model"
		model := readSysfsTrimmed(modelPath)
		if containsAny(model, vmIdentifiers) {
			return true
		}
	}
	return false
}

func checkPCI() bool {
	entries, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		vendorPath := "/sys/bus/pci/devices/" + entry.Name() + "/vendor"
		vendor := readSysfsTrimmed(vendorPath)
		vendorID := strings.TrimPrefix(vendor, "0x")
		for _, v := range vmPCIVendors {
			if vendorID == v {
				return true
			}
		}
	}
	return false
}

func checkTiming() bool {
	start := time.Now()
	sum := 0
	for i := 0; i < 100000; i++ {
		sum += i
	}
	elapsed := time.Since(start)
	_ = sum
	return elapsed > 10*time.Millisecond
}

func checkSystemProfiler() bool {
	return false
}

func checkIOKit() bool {
	return false
}

func checkRegistry() bool {
	return false
}

func checkWMI() bool {
	return false
}
