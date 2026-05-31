package typewipe

import (
	"crypto/rand"
	"fmt"
	"runtime"
)

// WipeOptions controls what metadata to destroy.
type WipeOptions struct {
	WipeTypelink  bool // Destroy .typelink section (type linkage info)
	WipeItab      bool // Destroy itab entries (interface method tables)
	WipeTypeNames bool // XOR-encrypt type name strings in ._type structs
	Key           byte // XOR key (0 = random)
}

// WipeAtInit should be called during init(). It finds and destroys
// Go type metadata in the running binary's memory.
// WARNING: This degrades reflection and panic output.
func WipeAtInit(opts WipeOptions) error {
	if opts.Key == 0 {
		var k [1]byte
		if _, err := rand.Read(k[:]); err != nil {
			return fmt.Errorf("typewipe: failed to generate key: %w", err)
		}
		if k[0] == 0 {
			k[0] = 0x5A
		}
		opts.Key = k[0]
	}

	if runtime.GOOS == "windows" {
		return fmt.Errorf("typewipe: not supported on windows")
	}

	return wipePlatform(opts)
}

func xorSlice(data []byte, key byte) {
	for i := range data {
		if data[i] != 0 {
			data[i] ^= key
		}
	}
}

func zeroSlice(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
