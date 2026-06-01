package strenc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestDeriveMasterKeyDeterministic(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	k1 := DeriveMasterKey(seed)
	k2 := DeriveMasterKey(seed)
	if k1 != k2 {
		t.Errorf("DeriveMasterKey not deterministic: %x vs %x", k1, k2)
	}
}

func TestDeriveMasterKeyDifferentSeeds(t *testing.T) {
	var s1, s2 [32]byte
	s1[0] = 1
	s2[0] = 2
	k1 := DeriveMasterKey(s1)
	k2 := DeriveMasterKey(s2)
	if k1 == k2 {
		t.Errorf("DeriveMasterKey produced same key for different seeds")
	}
}

func TestDeriveMasterKeyLengthAndFormat(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	key := DeriveMasterKey(seed)
	if key == [32]byte{} {
		t.Error("DeriveMasterKey returned zero key")
	}

	zeroKey := DeriveMasterKey([32]byte{})
	if zeroKey == [32]byte{} {
		t.Error("DeriveMasterKey returned zero key for zero seed")
	}
}

func TestEncryptEntryRoundtripViaPool(t *testing.T) {
	masterKeySeed := [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	plaintexts := []string{
		"hello",
		"sk-proj-FAKE-KEY-1234567890abcdef",
		"super-secret-license-key-DO-NOT-SHARE",
		"a",
		"",
	}

	var entries []Entry
	for i, pt := range plaintexts {
		var iv [16]byte
		iv[0] = byte(i)
		iv[15] = byte(i + 1)
		entries = append(entries, EncryptEntry(pt, deriveSubkey(masterKeySeed, iv), iv))
	}

	pool := NewPool(masterKeySeed, entries)
	if pool.StringCount() != len(plaintexts) {
		t.Fatalf("StringCount=%d, want %d", pool.StringCount(), len(plaintexts))
	}

	for i, want := range plaintexts {
		got := pool.GetString(i)
		if got != want {
			t.Errorf("GetString(%d) = %q, want %q", i, got, want)
		}
	}
}

func TestGetStringOutOfRange(t *testing.T) {
	pool := NewPool([32]byte{1}, nil)
	if got := pool.GetString(0); got != "" {
		t.Errorf("GetString(0) on empty pool = %q, want \"\"", got)
	}
	if got := pool.GetString(99); got != "" {
		t.Errorf("GetString(99) on empty pool = %q, want \"\"", got)
	}
}

func TestEncryptEntryCiphertextDiffersFromPlaintext(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var iv [16]byte

	entry := EncryptEntry("hello world", key, iv)
	if bytes.Equal(entry.Ciphertext, []byte("hello world")) {
		t.Error("ciphertext equals plaintext (no encryption?)")
	}
	if entry.IV != iv {
		t.Error("IV was modified by EncryptEntry")
	}
}

func TestPoolDecryptionFailsOnTamperedCiphertext(t *testing.T) {
	seed := [32]byte{0xAA, 0xBB}
	var iv [16]byte
	entry := EncryptEntry("secret", deriveSubkey(seed, iv), iv)

	tampered := make([]byte, len(entry.Ciphertext))
	copy(tampered, entry.Ciphertext)
	if len(tampered) > 16 {
		tampered[20] ^= 0x01
	}

	pool := NewPool(seed, []Entry{{Ciphertext: tampered, IV: iv}})
	if got := pool.GetString(0); got == "secret" {
		t.Error("GetString returned plaintext on tampered ciphertext (GCM should reject)")
	}
}

func deriveSubkey(seed [32]byte, iv [16]byte) [32]byte {
	master := DeriveMasterKey(seed)
	mac := hmac.New(sha256.New, master[:])
	mac.Write(iv[:])
	var sub [32]byte
	copy(sub[:], mac.Sum(nil))
	return sub
}
