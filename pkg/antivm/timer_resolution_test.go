package antivm

import "testing"

func TestCheckTimerResolution_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CheckTimerResolution panicked: %v", r)
		}
	}()
	_ = CheckTimerResolution()
}

func TestCheckTimerResolution_ReturnsBool(t *testing.T) {
	got := CheckTimerResolution()
	if got != true && got != false {
		t.Fatalf("CheckTimerResolution returned non-bool: %T(%v)", got, got)
	}
}

func TestCheckTimerResolution_Repeatable(t *testing.T) {
	const calls = 5
	for i := 0; i < calls; i++ {
		_ = CheckTimerResolution()
	}
}
