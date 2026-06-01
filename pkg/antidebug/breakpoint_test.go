package antidebug

import "testing"

func TestCheckHardwareBreakpointsNoPanic(t *testing.T) {
	_, _ = CheckHardwareBreakpoints()
}

func TestCheckHardwareBreakpointsConcurrent(t *testing.T) {
	for i := 0; i < 5; i++ {
		go func() { _, _ = CheckHardwareBreakpoints() }()
	}
}
