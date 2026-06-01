package antidebug

import (
	"testing"
	"time"
)

func TestInstallUninstallSingleStep(t *testing.T) {
	if err := InstallSingleStepDetector(); err != nil {
		t.Fatal(err)
	}
	defer UninstallSingleStepDetector()
	if err := InstallSingleStepDetector(); err != nil {
		t.Fatal(err)
	}
}

func TestWasSingleSteppedNoFalsePositive(t *testing.T) {
	if err := InstallSingleStepDetector(); err != nil {
		t.Fatal(err)
	}
	defer UninstallSingleStepDetector()
	time.Sleep(1100 * time.Millisecond)
	if WasSingleStepped() {
		t.Fatal("false positive: no SIGTRAP delivered but flagged")
	}
}
