package pclntab

import (
	"bytes"
	"testing"
)

func TestBytesEqual(t *testing.T) {
	cases := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{[]byte{1, 2}, []byte{1, 2, 3}, false},
		{[]byte{1, 2, 3}, []byte{1, 2}, false},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, false},
	}
	for i, c := range cases {
		if got := bytesEqual(c.a, c.b); got != c.want {
			t.Errorf("case %d: bytesEqual(%v, %v) = %v, want %v", i, c.a, c.b, got, c.want)
		}
	}
}

func TestReadUintBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		offset int
		size   int
		want   uint64
	}{
		{"32bit", []byte{0x78, 0x56, 0x34, 0x12}, 0, 4, 0x12345678},
		{"64bit", []byte{0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12}, 0, 8, 0x1234567890abcdef},
		{"out of range 4", []byte{0x01, 0x02}, 0, 4, 0},
		{"out of range 8", []byte{0x01, 0x02}, 0, 8, 0},
		{"unsupported size", []byte{0x01, 0x02, 0x03}, 0, 3, 0},
		{"negative offset returns 0", []byte{0x01, 0x02, 0x03, 0x04}, -1, 4, 0},
		{"offset past end", []byte{0x01, 0x02}, 100, 4, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := readUint(c.data, c.offset, c.size); got != c.want {
				t.Errorf("readUint(%v, %d, %d) = %d, want %d", c.data, c.offset, c.size, got, c.want)
			}
		})
	}
}

func TestPclntabParserRejectsUnknownMagic(t *testing.T) {
	tab := &pclntabParser{data: []byte{0x00, 0x00, 0x00, 0x00, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0}}
	if err := tab.parse(); err == nil {
		t.Error("expected error for unknown magic")
	}
}

func TestPclntabParserRejectsShortData(t *testing.T) {
	tab := &pclntabParser{data: []byte{0x01, 0x02, 0x03}}
	if err := tab.parse(); err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestPclntabParserValidGo118Magic(t *testing.T) {
	tab := &pclntabParser{data: append([]byte{0xF1, 0xFF, 0xFF, 0xF1, 0x00, 0x00, 0x08, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bytes.Repeat([]byte{0}, 16)...)}
	if err := tab.parse(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !tab.valid {
		t.Error("parser should mark valid")
	}
	if tab.ptrSize != 8 {
		t.Errorf("ptrSize = %d, want 8", tab.ptrSize)
	}
	if tab.quantum != 1 {
		t.Errorf("quantum = %d, want 1", tab.quantum)
	}
}

func TestPclntabParserNormalizesZeroPtrSize(t *testing.T) {
	tab := &pclntabParser{data: append([]byte{0xF1, 0xFF, 0xFF, 0xF1, 0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{0}, 16)...)}
	if err := tab.parse(); err != nil {
		t.Fatal(err)
	}
	if tab.ptrSize != 8 {
		t.Errorf("ptrSize should default to 8, got %d", tab.ptrSize)
	}
}

func TestPclntabParserNormalizesInvalidPtrSize(t *testing.T) {
	tab := &pclntabParser{data: append([]byte{0xF1, 0xFF, 0xFF, 0xF1, 0x00, 0x00, 0x06, 0x01}, bytes.Repeat([]byte{0}, 16)...)}
	if err := tab.parse(); err != nil {
		t.Fatal(err)
	}
	if tab.ptrSize != 8 {
		t.Errorf("ptrSize should default to 8, got %d", tab.ptrSize)
	}
}

func TestScrambleMagicChangesHeader(t *testing.T) {
	original := []byte{0xF1, 0xFF, 0xFF, 0xF1, 0x00, 0x00, 0x08, 0x01}
	data := append([]byte{}, original...)
	scrambleMagic(data)
	if bytes.Equal(data[:4], original[:4]) {
		t.Error("scrambleMagic did not change the first 4 bytes")
	}
	// Tail must be preserved
	if !bytes.Equal(data[4:], original[4:]) {
		t.Error("scrambleMagic modified bytes past the magic header")
	}
}

func TestScrambleMagicNoOpOnShortData(t *testing.T) {
	// No panic on short input.
	scrambleMagic([]byte{0x01, 0x02})
	scrambleMagic(nil)
}

func TestCorruptPclntabRejectsMissingSection(t *testing.T) {
	if _, err := CorruptPclntab("/nonexistent", CorruptOptions{}); err == nil {
		t.Error("expected error for nonexistent binary")
	}
}

func TestEncryptNamesRequiresValidTab(t *testing.T) {
	tab := &pclntabParser{data: []byte{0x00, 0x01, 0x02, 0x03}}
	if err := encryptNames(tab, 0x42); err == nil {
		t.Error("expected error for invalid pclntab")
	}
}
