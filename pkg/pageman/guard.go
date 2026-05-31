package pageman

import (
	"os"
	"runtime"
	"sync"
	"time"
)

type Guard struct {
	mu       sync.Mutex
	buffers  []*SecureBuffer
	interval time.Duration
	stop     chan struct{}
	stopped  bool
}

func NewGuard(interval time.Duration) *Guard {
	return &Guard{
		interval: interval,
		stop:     make(chan struct{}),
	}
}

func (g *Guard) Watch(buf *SecureBuffer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buffers = append(g.buffers, buf)
}

func (g *Guard) Start() {
	go g.loop()
}

func (g *Guard) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.stopped {
		return
	}

	g.stopped = true
	close(g.stop)
}

func (g *Guard) loop() {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()

	var prevMaps []byte

	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			g.enforceAutoLock()
			if runtime.GOOS == "linux" {
				prevMaps = g.checkMapsTampering(prevMaps)
			}
		}
	}
}

func (g *Guard) enforceAutoLock() {
	g.mu.Lock()
	bufs := make([]*SecureBuffer, len(g.buffers))
	copy(bufs, g.buffers)
	g.mu.Unlock()

	now := time.Now()
	for _, buf := range bufs {
		if buf.IsClosed() || buf.IsLocked() {
			continue
		}
		if now.Sub(buf.LastAccess()) > buf.AutoLockDuration() {
			buf.forceLock()
		}
	}
}

func (g *Guard) checkMapsTampering(prev []byte) []byte {
	current, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return prev
	}

	if prev != nil && !equalBytes(prev, current) {
		g.mu.Lock()
		for _, buf := range g.buffers {
			if !buf.IsClosed() && !buf.IsLocked() {
				buf.forceLock()
			}
		}
		g.mu.Unlock()
	}

	result := make([]byte, len(current))
	copy(result, current)
	return result
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
