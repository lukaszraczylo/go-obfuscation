package integrity

import (
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

var (
	expectedHash [32]byte
	hashIsSet    bool
	mu           sync.RWMutex
)

func SetExpectedHash(hash [32]byte) {
	mu.Lock()
	defer mu.Unlock()
	expectedHash = hash
	hashIsSet = true
}

// ClearExpectedHash disables integrity verification until the next
// SetExpectedHash call. Use this in test teardown or runtime toggles.
func ClearExpectedHash() {
	mu.Lock()
	defer mu.Unlock()
	expectedHash = [32]byte{}
	hashIsSet = false
}

func SetExpectedHashHex(hex string) error {
	if len(hex) != 64 {
		return fmt.Errorf("integrity: invalid hash hex length %d, want 64", len(hex))
	}
	var hash [32]byte
	for i := 0; i < 32; i++ {
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%x", &hash[i])
		if err != nil {
			return fmt.Errorf("integrity: invalid hash hex at byte %d: %w", i, err)
		}
	}
	SetExpectedHash(hash)
	return nil
}

func Verify() error {
	mu.RLock()
	set := hashIsSet
	mu.RUnlock()
	if !set {
		return nil
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("integrity: cannot determine executable path: %w", err)
	}

	hash, err := hashTextSection(selfPath)
	if err != nil {
		return fmt.Errorf("integrity: cannot hash text section: %w", err)
	}

	mu.RLock()
	expected := expectedHash
	mu.RUnlock()

	if hash != expected {
		return fmt.Errorf("integrity: binary has been tampered with")
	}
	return nil
}

func StartMonitor(interval time.Duration, onTamper func(error)) {
	mu.RLock()
	set := hashIsSet
	mu.RUnlock()
	if !set {
		return
	}

	go func() {
		jitter := time.Duration(randIntn(int(interval.Milliseconds()/2))) * time.Millisecond
		time.Sleep(jitter)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := Verify(); err != nil {
				if onTamper != nil {
					onTamper(err)
				}
				os.Exit(66)
			}
		}
	}()
}

func hashTextSection(path string) ([32]byte, error) {
	switch runtime.GOOS {
	case "linux":
		return hashTextELF(path)
	case "darwin":
		return hashTextMacho(path)
	case "windows":
		return hashTextPE(path)
	default:
		return hashWholeFile(path)
	}
}

func hashTextELF(path string) ([32]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	section := f.Section(".text")
	if section == nil {
		return hashWholeFile(path)
	}
	data, err := section.Data()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func hashTextMacho(path string) ([32]byte, error) {
	f, err := macho.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	for _, section := range f.Sections {
		if section.Name == "__text" {
			data, err := section.Data()
			if err != nil {
				return [32]byte{}, err
			}
			return sha256.Sum256(data), nil
		}
	}
	return hashWholeFile(path)
}

func hashTextPE(path string) ([32]byte, error) {
	f, err := pe.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	for _, section := range f.Sections {
		if section.Name == ".text" {
			data, err := section.Data()
			if err != nil {
				return [32]byte{}, err
			}
			return sha256.Sum256(data), nil
		}
	}
	return hashWholeFile(path)
}

func hashWholeFile(path string) ([32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func ComputeHashForEmbedding(path string) (string, error) {
	hash, err := hashTextSection(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash), nil
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return int(binary.BigEndian.Uint32(buf[:])) % n
}
