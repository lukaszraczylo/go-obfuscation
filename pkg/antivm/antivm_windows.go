//go:build windows

package antivm

import (
	"net"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var vmIdentifiers = []string{
	"VMware",
	"VirtualBox",
	"QEMU",
	"KVM",
	"Xen",
	"Microsoft Corporation",
	"Parallels",
	"VBOX",
	"Virtual HD",
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

func checkRegistry() bool {
	var h syscall.Handle
	keyPath, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\Disk\Enum`)
	err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		keyPath,
		0,
		syscall.KEY_READ,
		&h,
	)
	if err != nil {
		return false
	}
	defer syscall.RegCloseKey(h)

	var buf [512]uint16
	var bufLen uint32 = uint32(len(buf) * 2)
	var valType uint32

	name, _ := syscall.UTF16PtrFromString("0")
	err = syscall.RegQueryValueEx(
		h,
		name,
		nil,
		&valType,
		(*byte)(unsafe.Pointer(&buf[0])),
		&bufLen,
	)
	if err != nil {
		return false
	}

	val := syscall.UTF16ToString(buf[:])
	return containsAny(val, vmIdentifiers)
}

func checkWMI() bool {
	out, err := exec.Command("wmic", "computersystem", "get", "model").Output()
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

func checkSystemProfiler() bool {
	return false
}

func checkIOKit() bool {
	return false
}
