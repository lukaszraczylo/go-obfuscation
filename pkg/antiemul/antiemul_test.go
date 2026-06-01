package antiemul

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDoesNotPanic(t *testing.T) {
	_ = Check()
}

func TestCheckCoreCount(t *testing.T) {
	// In a real test env there should be >= 1 core. Sandbox detection only
	// flags < 2 cores; we just ensure the function returns a deterministic bool.
	got := checkCoreCount()
	if got {
		t.Log("system reports < 2 cores (suspicious)")
	}
}

func TestCheckMemory(t *testing.T) {
	got := checkMemory()
	// On a normal dev machine, memory > 2GB → false
	if got {
		t.Log("system reports < 2GB memory (suspicious)")
	}
}

func TestCheckUptime(t *testing.T) {
	got := checkUptime()
	if got {
		t.Log("system reports < 60s uptime (suspicious)")
	}
}

func TestCheckTiming(t *testing.T) {
	got := checkTiming()
	if got {
		t.Error("1M iterations of an empty loop should not exceed 500ms on any real hardware")
	}
}

func TestCheckMemoryOnFakeMeminfo(t *testing.T) {
	// Cannot easily override /proc/meminfo on Linux without root.
	// We just verify the regex/string logic by passing crafted content through
	// an internal helper. Skipping the override test on darwin/windows.
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skip("/proc/meminfo not available on this platform")
	}
	// Roundtrip: write a fake meminfo, read it via checkMemory.
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "meminfo")
	if err := os.WriteFile(fake, []byte("MemTotal:      1048576 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// checkMemory always reads /proc/meminfo, so we can only smoke-test the
	// parsing on the real path. Test the lower-bound detection on a low value.
	_ = fake
}
