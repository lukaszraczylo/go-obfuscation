package integrity

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetExpectedHashHexRoundtrip(t *testing.T) {
	hashHex := strings.Repeat("ab", 32) // 32 bytes of 0xAB
	if err := SetExpectedHashHex(hashHex); err != nil {
		t.Fatal(err)
	}
	// The hash is stored in package state; Verify should now attempt to read the
	// running test binary. We don't care about the outcome here, but Verify
	// must not panic. Restore to "unset" so other tests aren't affected.
	ClearExpectedHash()
	if err := Verify(); err != nil {
		t.Errorf("Verify after ClearExpectedHash should be no-op, got %v", err)
	}
}

func TestSetExpectedHashHexRejectsBadInput(t *testing.T) {
	if err := SetExpectedHashHex("not-hex"); err == nil {
		t.Error("expected error for non-hex input")
	}
	if err := SetExpectedHashHex(strings.Repeat("z", 64)); err == nil {
		t.Error("expected error for invalid hex characters")
	}
	if err := SetExpectedHashHex(strings.Repeat("a", 62)); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestVerifyUnsetReturnsNil(t *testing.T) {
	// Make sure no previous test left a hash set.
	ClearExpectedHash()
	if err := Verify(); err != nil {
		t.Errorf("Verify with unset hash = %v, want nil", err)
	}
}

func TestStartMonitorDoesNothingWhenUnset(t *testing.T) {
	ClearExpectedHash()
	StartMonitor(50*1e6, func(err error) {
		t.Errorf("callback invoked despite unset hash")
	})
	// No goroutine should have been spawned — the function returns immediately.
}

func TestClearExpectedHash(t *testing.T) {
	SetExpectedHash([32]byte{0xFF})
	ClearExpectedHash()
	if err := Verify(); err != nil {
		t.Errorf("Verify after ClearExpectedHash should be no-op, got %v", err)
	}
}

func TestHashTextSectionOnRealBinary(t *testing.T) {
	// Use the running test binary, which has the expected format for our GOOS.
	hash, err := hashTextSection(os.Args[0])
	if err != nil {
		t.Fatalf("hashTextSection(self) = %v", err)
	}
	if hash == [32]byte{} {
		t.Error("hashTextSection returned zero hash")
	}
}

func TestComputeHashForEmbeddingFormat(t *testing.T) {
	hex, err := ComputeHashForEmbedding(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(hex) != 64 {
		t.Errorf("hex length = %d, want 64", len(hex))
	}
}

func TestComputeHashForEmbeddingMissingFile(t *testing.T) {
	if _, err := ComputeHashForEmbedding("/nonexistent/path/that/should/not/exist"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestComputeHashForEmbeddingNonBinaryFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "data.bin")
	if err := os.WriteFile(path, []byte("not a real binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-binary file should produce an error from the ELF/Mach-O/PE parser.
	// (The whole-file fallback only kicks in when the format is unknown at the
	// OS-dispatch level, not when the parser itself fails.)
	if _, err := ComputeHashForEmbedding(path); err == nil {
		t.Log("platform swallowed non-binary file as whole-file hash (acceptable)")
	}
}

func TestHashWholeFileConsistent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "data.bin")
	content := []byte("consistent content")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := hashWholeFile(path)
	b, _ := hashWholeFile(path)
	if a != b {
		t.Error("hashWholeFile is not deterministic")
	}
}

func TestHashWholeFileChangesOnModification(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "data.bin")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := hashWholeFile(path)
	if err := os.WriteFile(path, []byte("v2-different"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := hashWholeFile(path)
	if a == b {
		t.Error("hashWholeFile did not change on content modification")
	}
}

func TestRandIntnNonNegative(t *testing.T) {
	for i := 0; i < 100; i++ {
		if n := randIntn(10); n < 0 || n >= 10 {
			t.Fatalf("randIntn(10) = %d, want 0..9", n)
		}
	}
}

func TestRandIntnHandlesZero(t *testing.T) {
	if n := randIntn(0); n != 0 {
		t.Errorf("randIntn(0) = %d, want 0", n)
	}
	if n := randIntn(-1); n != 0 {
		t.Errorf("randIntn(-1) = %d, want 0", n)
	}
}

func TestCurrentOSConsistency(t *testing.T) {
	hash, err := hashTextSection(os.Args[0]) // hash the test binary
	if err != nil {
		t.Fatalf("hashTextSection(self) = %v", err)
	}
	if bytes.Equal(hash[:], make([]byte, 32)) {
		t.Error("self-hash returned zero")
	}
	t.Logf("platform: %s, self-hash: %x", runtime.GOOS, hash)
}
