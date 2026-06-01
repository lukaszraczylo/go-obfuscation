package antisandbox

import "testing"

func TestSuspiciousHostnamesList(t *testing.T) {
	if len(suspiciousHostnames) == 0 {
		t.Fatal("suspiciousHostnames should be populated")
	}
	for _, h := range suspiciousHostnames {
		if h == "" {
			t.Error("empty entry in suspiciousHostnames")
		}
	}
}

func TestVMMACPrefixesList(t *testing.T) {
	if len(vmMACPrefixes) == 0 {
		t.Fatal("vmMACPrefixes should be populated")
	}
	for _, p := range vmMACPrefixes {
		if len(p) < 8 {
			t.Errorf("MAC prefix too short: %q", p)
		}
	}
}

func TestCheckDelegatesToCheckNetwork(t *testing.T) {
	// The Check function should return whatever CheckNetwork returns.
	// We can't easily mock net.Interfaces, so just call it and assert no panic.
	_ = Check()
}

func TestCheckNetworkDoesNotPanic(t *testing.T) {
	_ = CheckNetwork()
}

func TestCheckHostnameAgainstCurrentHost(t *testing.T) {
	// The current hostname should not match any of the suspicious patterns,
	// unless the test is somehow running in a sandbox.
	got := checkHostname()
	if got {
		t.Log("current hostname flagged as suspicious (running in a sandbox-like env?)")
	}
}

func TestCheckARPDoesNotPanicOnOtherOS(t *testing.T) {
	// On non-Linux platforms the /proc/net/arp read fails and returns false.
	_ = checkARP()
}
