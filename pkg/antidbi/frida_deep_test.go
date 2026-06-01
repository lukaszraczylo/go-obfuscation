package antidbi

import "testing"

func TestScanMemoryMapsForFridaNoPanic(t *testing.T) {
	_ = ScanMemoryMapsForFrida()
}

func TestScanMemoryMapsForFridaFalseInNormalState(t *testing.T) {
	if ScanMemoryMapsForFrida() {
		t.Skip("frida signatures detected in /proc/self/maps (test env may be hooked)")
	}
}

func TestScanNamedPipesForFridaNoPanic(t *testing.T) {
	_ = ScanNamedPipesForFrida()
}

func TestScanThreadsForFridaReadsCorrectly(t *testing.T) {
	_ = ScanThreadsForFrida()
}
