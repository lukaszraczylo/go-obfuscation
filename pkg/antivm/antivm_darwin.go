//go:build darwin

package antivm

import (
	"net"
	"os/exec"
	"strings"
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

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
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

func checkSystemProfiler() bool {
	out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err != nil {
		return false
	}
	return containsAny(string(out), vmIdentifiers)
}

func checkIOKit() bool {
	out, err := exec.Command("ioreg", "-l").Output()
	if err != nil {
		return false
	}
	return containsAny(string(out), vmIdentifiers)
}

func checkDMI() bool {
	return false
}

func checkCPUID() bool {
	return false
}

func checkDisk() bool {
	return false
}

func checkPCI() bool {
	return false
}

func checkTiming() bool {
	return false
}

func checkRegistry() bool {
	return false
}

func checkWMI() bool {
	return false
}
