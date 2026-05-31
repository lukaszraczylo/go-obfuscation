package pclntab

import (
	"crypto/rand"
	"fmt"
	"os"
)

// RuntimeCorrupt finds the running binary's pclntab in memory and XOR-encrypts
// all name strings. Call this during init() — the Go runtime has already used
// pclntab to resolve function pointers, so the program keeps working but
// post-init reverse engineering tools see garbage names.
//
// WARNING: Degrades panic stack traces (function names become unreadable).
func RuntimeCorrupt(key byte) error {
	if key == 0 {
		var k [1]byte
		if _, err := rand.Read(k[:]); err != nil {
			return fmt.Errorf("pclntab: failed to generate key: %w", err)
		}
		if k[0] == 0 {
			k[0] = 0x42
		}
		key = k[0]
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("pclntab: cannot determine executable: %w", err)
	}

	return runtimeCorrupt(selfPath, key)
}
