package antisandbox

import (
	"net"
	"os"
	"strings"
)

var suspiciousHostnames = []string{
	"sandbox", "malware", "cuckoo", "analysis", "sandox", "test",
}

var vmMACPrefixes = []string{
	"00:0c:29", "08:00:27", "52:54:00", "00:1c:42",
}

func CheckNetwork() bool {
	if checkInterfaces() {
		return true
	}
	if checkMACPrefixes() {
		return true
	}
	if checkHostname() {
		return true
	}
	if checkARP() {
		return true
	}
	return false
}

func checkInterfaces() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	return len(ifaces) <= 1
}

func checkMACPrefixes() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := strings.ToLower(iface.HardwareAddr.String())
		for _, prefix := range vmMACPrefixes {
			if strings.HasPrefix(mac, prefix) {
				return true
			}
		}
	}
	return false
}

func checkHostname() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	lower := strings.ToLower(hostname)
	for _, suspicious := range suspiciousHostnames {
		if strings.Contains(lower, suspicious) {
			return true
		}
	}
	return false
}

func checkARP() bool {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	return len(lines) <= 1
}
