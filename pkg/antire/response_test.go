package antire

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SevInfo, "info"},
		{SevWarn, "warn"},
		{SevCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.sev.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestSetPolicyAndTrigger(t *testing.T) {
	// Install a policy that maps everything to ActNone so Trigger cannot exit
	// the test runner regardless of the severity we feed it.
	SetPolicy(map[Severity]Action{
		SevInfo:     ActNone,
		SevWarn:     ActNone,
		SevCritical: ActNone,
	})

	for _, sev := range []Severity{SevInfo, SevWarn, SevCritical} {
		Trigger("test-check", sev)
	}
}

func TestSetPolicyRestoresDefault(t *testing.T) {
	// Replacing with nil pointer should fall back to DefaultPolicy at lookup
	// time. Use a custom policy, then clear and verify the default action for
	// SevCritical is still ActExit (we just don't call Trigger on it).
	SetPolicy(map[Severity]Action{
		SevInfo:     ActNone,
		SevWarn:     ActLog,
		SevCritical: ActNone,
	})

	if got := getPolicy()[SevCritical]; got != ActNone {
		t.Fatalf("custom policy not in effect: SevCritical = %d", got)
	}

	// Reset by storing nil; getPolicy should fall back to defaults.
	policyMu.Store(nil)
	if got := getPolicy()[SevCritical]; got != ActExit {
		t.Fatalf("default policy not restored: SevCritical = %d, want ActExit(%d)", got, ActExit)
	}
}

func TestTriggerWithActLogDoesNotExit(t *testing.T) {
	policyMu.Store(nil) // ensure default policy
	if getPolicy()[SevInfo] != ActLog {
		t.Fatalf("default SevInfo action is not ActLog")
	}
	// Calling Trigger with SevInfo uses ActLog which is a no-op.
	Trigger("smoke-test", SevInfo)
}
