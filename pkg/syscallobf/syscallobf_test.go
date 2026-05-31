package syscallobf

import "testing"

func TestEncodeDecodeTrap(t *testing.T) {
	initDispatchKey()

	tests := []uintptr{0, 1, 39, 62, 101, 0xDEAD, 0xFFFFFFFF}
	for _, num := range tests {
		encoded := EncodeTrap(num)
		if encoded == num {
			t.Errorf("EncodeTrap(%d) should not equal input", num)
		}
		decoded := DecodeTrap(encoded)
		if decoded != num {
			t.Errorf("DecodeTrap(EncodeTrap(%d)) = %d, want %d", num, decoded, num)
		}
	}
}

func TestEncodedSyscall(t *testing.T) {
	initDispatchKey()

	enc := NewEncodedSyscall(101)
	if enc.Trap() != 101 {
		t.Errorf("EncodedSyscall.Trap() = %d, want 101", enc.Trap())
	}
}

func TestDispatchKeyNonZero(t *testing.T) {
	initDispatchKey()
	if dispatchKey == 0 {
		t.Error("dispatchKey should not be 0")
	}
}
