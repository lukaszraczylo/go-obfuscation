package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func pack(t *testing.T, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = "."
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return so.String(), se.String(), ee.ExitCode()
		}
		return so.String(), se.String(), -1
	}
	return so.String(), se.String(), 0
}

func TestPackUnpackRoundtrip(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.bin")
	outPath := filepath.Join(dir, "packed.go")
	stubOut := filepath.Join(dir, "decoded.bin")

	payload := []byte("packer-mvp-roundtrip-\x00\x01\x02binary\xff")
	if err := os.WriteFile(inPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	// Use a fixed key so the test is deterministic.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	stdout, stderr, code := pack(t, "-in", inPath, "-out", outPath, "-key", hex.EncodeToString(key))
	if code != 0 {
		t.Fatalf("packer exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// Run the generated stub with go run, capturing stdout.
	run := exec.Command("go", "run", outPath)
	var runOut, runErr bytes.Buffer
	run.Stdout = &runOut
	run.Stderr = &runErr
	if err := run.Run(); err != nil {
		t.Fatalf("stub run failed: %v\nstderr: %s", err, runErr.String())
	}

	_ = stubOut
	if !bytes.Equal(runOut.Bytes(), payload) {
		t.Fatalf("decoded mismatch:\n got %x\nwant %x", runOut.Bytes(), payload)
	}
}

func TestPackInvalidKey(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.bin")
	outPath := filepath.Join(dir, "packed.go")
	if err := os.WriteFile(inPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-hex string.
	_, _, code := pack(t, "-in", inPath, "-out", outPath, "-key", "zzznothex")
	if code == 0 {
		t.Fatal("expected non-zero exit for invalid hex key")
	}

	// Valid hex, wrong length.
	_, _, code = pack(t, "-in", inPath, "-out", outPath, "-key", "deadbeef")
	if code == 0 {
		t.Fatal("expected non-zero exit for wrong-length key")
	}
}

func TestPackMissingFlags(t *testing.T) {
	_, _, code := pack(t)
	if code == 0 {
		t.Fatal("expected non-zero exit when -in/-out missing")
	}
	_, _, code = pack(t, "-in", "x")
	if code == 0 {
		t.Fatal("expected non-zero exit when -out missing")
	}
}
