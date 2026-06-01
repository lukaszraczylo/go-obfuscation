package smc

import (
	"bytes"
	"sync"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	code := []byte("hello self-modifying world")
	key := []byte("k3y-mvp-2026")

	enc, err := Encrypt(code, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(enc, code) {
		t.Fatal("ciphertext matches plaintext (no encryption)")
	}

	dec, err := Decrypt(enc, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec, code) {
		t.Fatalf("roundtrip mismatch: got %q want %q", dec, code)
	}
}

func TestEncryptEmptyKey(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := Encrypt([]byte("x"), []byte{}); err == nil {
		t.Fatal("expected error for zero-length key")
	}
}

func TestExecuteEmpty(t *testing.T) {
	if err := Execute(nil, []byte("k")); err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestExecuteEmptyKey(t *testing.T) {
	if err := Execute([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestExecuteFuncNoPanic(t *testing.T) {
	var ran bool
	fn := func() { ran = true }
	if err := ExecuteFunc(fn, []byte("k")); err != nil {
		t.Fatalf("ExecuteFunc: %v", err)
	}
	if !ran {
		t.Fatal("function did not run")
	}
}

func TestExecuteConcurrent(t *testing.T) {
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	key := []byte("shared-key")

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
			if err := Execute(payload, key); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Execute: %v", err)
	}
}
