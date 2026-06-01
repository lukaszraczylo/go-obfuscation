package integrity

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// Monitor periodically re-hashes a region of memory (typically the process's
// .text section) and reports drift to callers via Check().
type Monitor struct {
	textStart uintptr
	textSize  int
	hash      [32]byte
	interval  time.Duration
	stop      chan struct{}
	done      chan struct{}
	mu        sync.RWMutex
	drift     bool
}

// StartMemoryRegionMonitor computes the initial SHA-256 of the supplied
// in-memory region and starts a background goroutine that re-hashes every
// interval. If drift is detected the monitor stops itself and Check() will
// return false.
//
// Distinct from StartMonitor(interval, onTamper) in integrity.go, which
// re-hashes the binary file on disk via os.Executable(). This function
// operates on a live memory region pointed to by textStart.
func StartMemoryRegionMonitor(textStart uintptr, textSize int, interval time.Duration) (*Monitor, error) {
	if textSize <= 0 || interval <= 0 {
		return nil, fmt.Errorf("integrity: invalid monitor params")
	}
	m := &Monitor{
		textStart: textStart,
		textSize:  textSize,
		interval:  interval,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	h, err := hashRegion(textStart, textSize)
	if err != nil {
		return nil, err
	}
	m.hash = h
	go m.run()
	return m, nil
}

func (m *Monitor) run() {
	defer close(m.done)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			h, err := hashRegion(m.textStart, m.textSize)
			if err != nil {
				continue
			}
			m.mu.Lock()
			if h != m.hash {
				m.drift = true
				m.mu.Unlock()
				return
			}
			m.mu.Unlock()
		}
	}
}

// Stop halts the background re-hash loop and waits for it to exit.
func (m *Monitor) Stop() {
	close(m.stop)
	<-m.done
}

// Check re-hashes the region and reports whether it matches the baseline.
// It returns false (with no error) once drift has been observed.
func (m *Monitor) Check() (bool, error) {
	m.mu.RLock()
	drift := m.drift
	m.mu.RUnlock()
	if drift {
		return false, nil
	}
	h, err := hashRegion(m.textStart, m.textSize)
	if err != nil {
		return false, err
	}
	return h == m.hash, nil
}

//go:nocheckptr
func hashRegion(addr uintptr, size int) ([32]byte, error) {
	var zero [32]byte
	if size <= 0 {
		return zero, fmt.Errorf("integrity: invalid size")
	}
	// Direct uintptr -> unsafe.Pointer conversion. Combined with
	// //go:nocheckptr above, this is also compatible with `go vet
	// -unsafeptr=false` for builds that enable the runtime checkptr
	// instrumentation (e.g. `go test -race`).
	src := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return sha256.Sum256(src), nil
}
