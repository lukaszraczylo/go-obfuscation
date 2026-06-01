package integrity

import (
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestStartMemoryRegionMonitorInvalidParams(t *testing.T) {
	if _, err := StartMemoryRegionMonitor(0, 0, 0); err == nil {
		t.Error("expected error for zero size/interval")
	}
	if _, err := StartMemoryRegionMonitor(0, 16, 0); err == nil {
		t.Error("expected error for zero interval")
	}
	if _, err := StartMemoryRegionMonitor(0, -1, time.Millisecond); err == nil {
		t.Error("expected error for negative size")
	}
}

func TestMonitorStartStopAndCheck(t *testing.T) {
	// Use a heap-allocated buffer as the "text" region so the address stays
	// valid for the lifetime of the test (and for the goroutine).
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	ptr := uintptr(unsafe.Pointer(&buf[0]))

	m, err := StartMemoryRegionMonitor(ptr, len(buf), 5*time.Millisecond)
	if err != nil {
		t.Fatalf("StartMemoryRegionMonitor = %v", err)
	}

	ok, err := m.Check()
	if err != nil {
		t.Fatalf("Check = %v", err)
	}
	if !ok {
		t.Error("Check returned false on unmodified buffer")
	}

	// Let a few ticks pass; buffer is still untouched, so no drift should
	// have been recorded. We can't observe the internal `drift` flag
	// directly, but Check() should still report true after a short sleep.
	time.Sleep(25 * time.Millisecond)
	ok, err = m.Check()
	if err != nil {
		t.Fatalf("Check (post-sleep) = %v", err)
	}
	if !ok {
		t.Error("Check returned false after sleeping on unmodified buffer")
	}

	m.Stop()

	// Double-stop would panic on close(closed channel); just guard with a
	// flag-style check that Stop is idempotent w.r.t. subsequent Check.
	ok, err = m.Check()
	if err != nil {
		t.Fatalf("Check (post-stop) = %v", err)
	}
	if !ok {
		t.Error("Check returned false after Stop on unmodified buffer")
	}
}

func TestMonitorDetectsDrift(t *testing.T) {
	// Build a 256-byte region, hash it, then mutate the region and re-hash to
	// confirm hashRegion is actually reading the bytes pointed to.
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = 0xAA
	}
	ptr := uintptr(unsafe.Pointer(&buf[0]))

	h1, err := hashRegion(ptr, len(buf))
	if err != nil {
		t.Fatalf("hashRegion (initial) = %v", err)
	}

	buf[0] = 0xBB
	h2, err := hashRegion(ptr, len(buf))
	if err != nil {
		t.Fatalf("hashRegion (mutated) = %v", err)
	}
	if h1 == h2 {
		t.Error("hashRegion did not detect single-byte mutation")
	}
}

func TestMonitorRaceFree(t *testing.T) {
	// Exercises Check + Stop from multiple goroutines under -race.
	buf := make([]byte, 1024)
	ptr := uintptr(unsafe.Pointer(&buf[0]))

	m, err := StartMemoryRegionMonitor(ptr, len(buf), 2*time.Millisecond)
	if err != nil {
		t.Fatalf("StartMemoryRegionMonitor = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = m.Check()
			}
		}()
	}
	wg.Wait()
	m.Stop()
}
