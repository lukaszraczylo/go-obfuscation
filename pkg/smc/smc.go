// Package smc provides MVP self-modifying code primitives.
//
// MVP scope: XOR-encrypt a function payload, hold it locked in a
// pageman.SecureBuffer, decrypt briefly inside an Access callback,
// re-encrypt on callback return. Production SMC needs per-arch
// assembly for atomic decrypt+execute (not in MVP).
package smc

import (
	"fmt"

	"github.com/lukaszraczylo/go-obfuscation/pkg/pageman"
)

// Encrypt XOR-encrypts code with key. key must be non-empty.
func Encrypt(code, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("smc: empty key")
	}
	out := make([]byte, len(code))
	for i, b := range code {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

// Decrypt reverses Encrypt.
func Decrypt(code, key []byte) ([]byte, error) {
	return Encrypt(code, key) // XOR is symmetric
}

// Execute demonstrates the encrypt/decrypt cycle on an encrypted payload.
//
// It parks the payload inside a pageman.SecureBuffer (locked at rest),
// unlocks it via Access to do an in-place decrypt, then locks it back.
// The "execute" step is a no-op: jumping to arbitrary decrypted bytes
// would require platform-specific func() cast and an RX window, both
// outside MVP scope.
//
// MVP limitation: the brief window where plaintext exists inside the
// Access callback is observable. Production needs arch-specific atomic
// decrypt+exec.
func Execute(encrypted, key []byte) error {
	if len(encrypted) == 0 {
		return fmt.Errorf("smc: empty encrypted payload")
	}
	if len(key) == 0 {
		return fmt.Errorf("smc: empty key")
	}

	sb := pageman.NewSecureBuffer(encrypted, 0)
	defer sb.Close()

	// First cycle: unlock -> decrypt in place (verify) -> relock.
	if err := sb.Access(func(plain []byte) {
		for i, b := range plain {
			plain[i] = b ^ key[i%len(key)]
		}
	}); err != nil {
		return fmt.Errorf("smc: decrypt access failed: %w", err)
	}

	// Second cycle: unlock -> re-encrypt in place -> relock.
	if err := sb.Access(func(plain []byte) {
		for i, b := range plain {
			plain[i] = b ^ key[i%len(key)]
		}
	}); err != nil {
		return fmt.Errorf("smc: re-encrypt access failed: %w", err)
	}

	return nil
}

// ExecuteFunc calls fn after running it through a no-op encrypt/decrypt
// cycle on a side buffer. MVP: the function is invoked normally; the
// cycle just exercises the smc primitives around it.
func ExecuteFunc(fn func(), key []byte) error {
	// Build a synthetic payload, run the cycle, then call the function.
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := Execute(payload, key); err != nil {
		return err
	}
	defer func() { _ = recover() }()
	fn()
	return nil
}
