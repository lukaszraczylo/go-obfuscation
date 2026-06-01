package antivm

import (
	"time"
)

// CheckTimerResolution measures time.Now() granularity. Real CPUs typically
// have < 1us resolution; VMs often have 1ms or 15ms (Windows default).
// Returns true if resolution appears native (< 1ms), false if VM-like.
func CheckTimerResolution() bool {
	var minDelta time.Duration = time.Hour
	const samples = 100
	var last = time.Now()
	for i := 0; i < samples; i++ {
		start := time.Now()
		for time.Since(start) < time.Microsecond {
			_ = start
		}
		now := time.Now()
		if d := now.Sub(last); d > 0 && d < minDelta {
			minDelta = d
		}
		last = now
	}
	return minDelta < time.Millisecond
}
