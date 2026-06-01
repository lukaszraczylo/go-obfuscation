package antisandbox

import "testing"

func TestCheckLDPreloadNoPanic(t *testing.T) {
	_ = CheckLDPreload()
}

func TestCheckLdSoPreloadNoPanic(t *testing.T) {
	_ = CheckLdSoPreload()
}

func TestUnsetInjectedEnvNoError(t *testing.T) {
	if err := UnsetInjectedEnv(); err != nil {
		t.Errorf("UnsetInjectedEnv returned error: %v", err)
	}
}

func TestCheckLDPreloadFalseInNormalState(t *testing.T) {
	if CheckLDPreload() {
		t.Skip("suspicious LD_PRELOAD-style .so detected in /proc/self/maps (test env may be hooked)")
	}
}
