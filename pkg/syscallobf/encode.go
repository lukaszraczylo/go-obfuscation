package syscallobf

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

var (
	dispatchKey  uint64
	dispatchOnce sync.Once
)

func initDispatchKey() {
	dispatchOnce.Do(func() {
		var buf [8]byte
		rand.Read(buf[:])
		dispatchKey = binary.LittleEndian.Uint64(buf[:])
		if dispatchKey == 0 {
			dispatchKey = 0xDEADBEEFCAFEBABE
		}
	})
}

func EncodeTrap(num uintptr) uintptr {
	initDispatchKey()
	return uintptr(uint64(num) ^ dispatchKey)
}

func DecodeTrap(encoded uintptr) uintptr {
	return uintptr(uint64(encoded) ^ dispatchKey)
}

type encodedSyscall struct {
	encoded uintptr
}

func NewEncodedSyscall(num uintptr) encodedSyscall {
	return encodedSyscall{encoded: EncodeTrap(num)}
}

func (e encodedSyscall) Trap() uintptr {
	return DecodeTrap(e.encoded)
}
