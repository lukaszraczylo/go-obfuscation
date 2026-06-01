package stringcrypt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	cases := []string{
		"",
		"x",
		"hello world",
		"sk-proj-FAKE-KEY-1234567890abcdef",
		"unicode: \u00e9\u4e2d\u6587",
		"line1\nline2\ttabbed",
	}
	for _, pt := range cases {
		enc := Encrypt(pt)
		if pt != "" && bytes.Equal(enc.ciphertext, []byte(pt)) {
			t.Errorf("ciphertext equals plaintext for %q", pt)
		}
		if got := enc.Decrypt(); got != pt {
			t.Errorf("Decrypt() = %q, want %q", got, pt)
		}
	}
}

func TestEncryptUniqueKeys(t *testing.T) {
	pt := "same plaintext"
	a := Encrypt(pt)
	b := Encrypt(pt)
	if bytes.Equal(a.key, b.key) {
		t.Error("two Encrypt calls produced identical keys (low probability event, but should not happen)")
	}
	if bytes.Equal(a.ciphertext, b.ciphertext) {
		t.Error("two Encrypt calls produced identical ciphertext (keys should differ)")
	}
}

func TestEncryptedStringB64Roundtrip(t *testing.T) {
	enc := Encrypt("hello")
	ct, err := base64.StdEncoding.DecodeString(enc.CiphertextB64())
	if err != nil {
		t.Fatalf("CiphertextB64() invalid base64: %v", err)
	}
	if !bytes.Equal(ct, enc.ciphertext) {
		t.Error("CiphertextB64() does not roundtrip to raw ciphertext")
	}
	ky, err := base64.StdEncoding.DecodeString(enc.KeyB64())
	if err != nil {
		t.Fatalf("KeyB64() invalid base64: %v", err)
	}
	if !bytes.Equal(ky, enc.key) {
		t.Error("KeyB64() does not roundtrip to raw key")
	}
}

func TestRandomIdent(t *testing.T) {
	const prefix = "x"
	const length = 5
	id := RandomIdent(prefix, length)
	if len(id) != len(prefix)+length {
		t.Errorf("RandomIdent len = %d, want %d (got %q)", len(id), len(prefix)+length, id)
	}
	if id[:len(prefix)] != prefix {
		t.Errorf("RandomIdent prefix mismatch: %q", id)
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for _, r := range id[len(prefix):] {
		if !bytes.ContainsRune([]byte(charset), r) {
			t.Errorf("RandomIdent contains unexpected char %q in %q", r, id)
		}
	}
}

func TestRandomIdentUniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := RandomIdent("_p", 6)
		if _, dup := seen[id]; dup {
			t.Fatalf("RandomIdent collision after %d iterations: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestRandomIdentZeroLength(t *testing.T) {
	id := RandomIdent("p_", 0)
	if id != "p_" {
		t.Errorf("RandomIdent with 0 length = %q, want %q", id, "p_")
	}
}

func TestGenerateRuntimeDecryptCallStructure(t *testing.T) {
	src := GenerateRuntimeDecryptCall("aGVsbG8=", "a2V5")
	if src == "" {
		t.Error("GenerateRuntimeDecryptCall returned empty string")
	}
	for _, want := range []string{"base64.StdEncoding", "DecodeString", "return", "string(_pt)"} {
		if !bytes.Contains([]byte(src), []byte(want)) {
			t.Errorf("GenerateRuntimeDecryptCall missing %q in output:\n%s", want, src)
		}
	}
}
