package pageman

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestNewSecureBufferStartsLocked(t *testing.T) {
	sb := NewSecureBuffer([]byte("hello"), 0)
	defer sb.Close()

	if !sb.IsLocked() {
		t.Error("new buffer should be locked")
	}
	if sb.IsClosed() {
		t.Error("new buffer should not be closed")
	}
}

func TestNewSecureBufferZeroesInput(t *testing.T) {
	input := []byte("secret")
	NewSecureBuffer(input, 0)
	if bytes.Contains(input, []byte("secret")) {
		t.Errorf("NewSecureBuffer did not zero caller's input: %q", input)
	}
}

func TestAccessProvidesPlaintext(t *testing.T) {
	sb := NewSecureBuffer([]byte("hello world"), 0)
	defer sb.Close()

	var seen string
	if err := sb.Access(func(b []byte) {
		seen = string(b)
	}); err != nil {
		t.Fatal(err)
	}
	if seen != "hello world" {
		t.Errorf("Access plaintext = %q, want %q", seen, "hello world")
	}
}

func TestAccessRelocksAfterCallback(t *testing.T) {
	sb := NewSecureBuffer([]byte("hello"), 0)
	defer sb.Close()

	_ = sb.Access(func(b []byte) {})
	if !sb.IsLocked() {
		t.Error("Access should re-lock after callback")
	}
}

func TestUnlockLockCycle(t *testing.T) {
	sb := NewSecureBuffer([]byte("test"), 0)
	defer sb.Close()

	if err := sb.Unlock(); err != nil {
		t.Fatal(err)
	}
	if sb.IsLocked() {
		t.Error("buffer should be unlocked")
	}
	if err := sb.Lock(); err != nil {
		t.Fatal(err)
	}
	if !sb.IsLocked() {
		t.Error("buffer should be locked")
	}
}

func TestUnlockAlreadyUnlockedReturnsError(t *testing.T) {
	sb := NewSecureBuffer([]byte("x"), 0)
	defer sb.Close()
	if err := sb.Unlock(); err != nil {
		t.Fatal(err)
	}
	err := sb.Unlock()
	if !errors.Is(err, ErrAlreadyUnlocked) {
		t.Errorf("expected ErrAlreadyUnlocked, got %v", err)
	}
}

func TestLockAlreadyLockedReturnsError(t *testing.T) {
	sb := NewSecureBuffer([]byte("x"), 0)
	defer sb.Close()
	err := sb.Lock()
	if !errors.Is(err, ErrAlreadyLocked) {
		t.Errorf("expected ErrAlreadyLocked, got %v", err)
	}
}

func TestAccessOnClosedBufferReturnsError(t *testing.T) {
	sb := NewSecureBuffer([]byte("x"), 0)
	sb.Close()
	err := sb.Access(func(b []byte) {})
	if !errors.Is(err, ErrClosed) {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	sb := NewSecureBuffer([]byte("x"), 0)
	sb.Close()
	sb.Close() // should not panic
	if !sb.IsClosed() {
		t.Error("buffer should be closed")
	}
}

func TestEmptyBuffer(t *testing.T) {
	sb := NewSecureBuffer(nil, 0)
	defer sb.Close()
	if !sb.IsLocked() {
		t.Error("empty buffer should be locked initially")
	}
	var seen []byte
	if err := sb.Access(func(b []byte) { seen = b }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Errorf("expected empty plaintext, got %q", seen)
	}
}

func TestAutoLockDuration(t *testing.T) {
	d := 5 * time.Second
	sb := NewSecureBuffer([]byte("x"), d)
	defer sb.Close()
	if got := sb.AutoLockDuration(); got != d {
		t.Errorf("AutoLockDuration = %v, want %v", got, d)
	}
}

func TestGuardLifecycle(t *testing.T) {
	g := NewGuard(50 * time.Millisecond)
	g.Start()
	g.Watch(NewSecureBuffer([]byte("a"), 0))
	time.Sleep(120 * time.Millisecond)
	g.Stop()
	// Stop must be safe to call once
	g.Stop()
}

func TestGuardStopWithoutStart(t *testing.T) {
	g := NewGuard(50 * time.Millisecond)
	g.Stop() // must not panic
}

func TestRotateUnrotateRoundtrip(t *testing.T) {
	cases := []byte{0x00, 0xFF, 0xAA, 0x55, 0x01, 0x80}
	for pos := 0; pos < 8; pos++ {
		for _, in := range cases {
			rot := rotateKey(in, pos)
			back := unrotateKey(rot, pos)
			if back != in {
				t.Errorf("rotate/unrotate for pos=%d input=0x%02X: got 0x%02X", pos, in, back)
			}
		}
	}
}
