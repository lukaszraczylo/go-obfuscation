package pclntab

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

var pclntabMagics = [][]byte{
	{0xF1, 0xFF, 0xFF, 0xFA}, // Go 1.2 - 1.15
	{0xF1, 0xFF, 0xFF, 0xF0}, // Go 1.16 - 1.17
	{0xF1, 0xFF, 0xFF, 0xF1}, // Go 1.18+
}

type CorruptOptions struct {
	EncryptNames  bool
	ScrambleMagic bool
	InjectFake    bool
	Key           byte
}

func CorruptPclntab(binaryPath string, opts CorruptOptions) ([]byte, error) {
	if opts.Key == 0 {
		var k [1]byte
		if _, err := rand.Read(k[:]); err != nil {
			return nil, fmt.Errorf("pclntab: failed to generate key: %w", err)
		}
		if k[0] == 0 {
			k[0] = 0x42
		}
		opts.Key = k[0]
	}

	data, err := readPclntabSection(binaryPath)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("pclntab: .gopclntab section not found in %s", binaryPath)
	}

	corrupted := make([]byte, len(data))
	copy(corrupted, data)

	tab := &pclntabParser{data: corrupted}

	if opts.ScrambleMagic {
		scrambleMagic(corrupted)
	}

	if opts.EncryptNames {
		if err := encryptNames(tab, opts.Key); err != nil {
			return nil, fmt.Errorf("pclntab: failed to encrypt names: %w", err)
		}
	}

	if opts.InjectFake {
		corrupted = injectFakeEntries(corrupted)
	}

	return corrupted, nil
}

type pclntabParser struct {
	data      []byte
	magic     []byte
	quantum   uint8
	ptrSize   uint8
	nfiles    uint32
	nameOff   uint32
	strtabOff uint32
	valid     bool
}

func (p *pclntabParser) parse() error {
	if len(p.data) < 16 {
		return fmt.Errorf("pclntab: data too small (%d bytes)", len(p.data))
	}

	p.magic = p.data[:4]
	found := false
	for _, m := range pclntabMagics {
		if bytesEqual(p.magic, m) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("pclntab: unrecognized magic: %x", p.magic)
	}

	p.ptrSize = p.data[6]
	p.quantum = p.data[7]

	if p.ptrSize == 0 || (p.ptrSize != 4 && p.ptrSize != 8) {
		p.ptrSize = 8
	}
	if p.quantum == 0 {
		p.quantum = 1
	}

	if bytesEqual(p.magic, pclntabMagics[2]) {
		if len(p.data) >= 20 {
			p.nfiles = binary.LittleEndian.Uint32(p.data[16:20])
		}
	}

	p.valid = true
	return nil
}

func scrambleMagic(data []byte) {
	if len(data) < 4 {
		return
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	for i := 0; i < 4; i++ {
		data[i] = rnd[i]
	}
}

func encryptNames(tab *pclntabParser, key byte) error {
	if err := tab.parse(); err != nil {
		return err
	}

	nameStart, nameEnd := findNameRegion(tab)
	if nameStart == 0 || nameEnd == 0 || nameStart >= nameEnd {
		return fmt.Errorf("pclntab: could not locate name region")
	}

	if nameEnd > uint32(len(tab.data)) {
		nameEnd = uint32(len(tab.data))
	}

	for i := nameStart; i < nameEnd; i++ {
		if tab.data[i] != 0 {
			tab.data[i] ^= key
		}
	}

	return nil
}

func findNameRegion(tab *pclntabParser) (uint32, uint32) {
	data := tab.data
	ptrSize := int(tab.ptrSize)

	if bytesEqual(tab.magic, pclntabMagics[2]) {
		if len(data) < 16+4+4*int(ptrSize) {
			return 0, 0
		}

		offset := 16 + 4
		_ = readUint(data, offset, ptrSize) // nfunc
		offset += ptrSize
		offset += ptrSize // nfiles (Go 1.18 already read above)

		_ = readUint(data, offset, ptrSize) // textStart
		offset += ptrSize

		funcnametab := readUint(data, offset, ptrSize)
		offset += ptrSize
		_ = readUint(data, offset, ptrSize) // cutab
		offset += ptrSize
		_ = readUint(data, offset, ptrSize) // filetab
		offset += ptrSize
		_ = readUint(data, offset, ptrSize) // pctab
		offset += ptrSize
		pclntab := readUint(data, offset, ptrSize)

		_ = pclntab

		nameStart := uint32(funcnametab)
		nameEnd := nameStart
		for i := nameStart; i < uint32(len(data)); i++ {
			if data[i] == 0 {
				if i+1 < uint32(len(data)) && data[i+1] == 0 {
					nameEnd = i
					break
				}
			}
		}
		if nameEnd == nameStart {
			nameEnd = uint32(len(data))
		}

		return nameStart, nameEnd
	}

	return findNameRegionLegacy(tab)
}

func findNameRegionLegacy(tab *pclntabParser) (uint32, uint32) {
	data := tab.data
	offset := 8 + 4 + 4

	if bytesEqual(tab.magic, pclntabMagics[1]) {
		offset += 4
	}

	if offset+8 > len(data) {
		return 0, 0
	}

	nameOff := binary.LittleEndian.Uint32(data[offset : offset+4])
	_ = binary.LittleEndian.Uint32(data[offset+4 : offset+8])

	nameStart := nameOff
	nameEnd := nameStart
	for i := nameStart; i < uint32(len(data)); i++ {
		if data[i] == 0 {
			if i+1 < uint32(len(data)) && data[i+1] == 0 {
				nameEnd = i
				break
			}
		}
	}
	if nameEnd == nameStart {
		nameEnd = uint32(len(data))
	}

	return nameStart, nameEnd
}

func injectFakeEntries(data []byte) []byte {
	fakeEntries := make([]byte, 256)
	_, _ = rand.Read(fakeEntries)

	fakeNames := []string{
		"runtime.fakeGoroutine",
		"crypto/internal.init",
		"main.processRequest",
		"net/http.handleConn",
		"google.golang.org/grpc.recvMsg",
		"github.com/user/repo.processData",
	}

	offset := 0
	for _, name := range fakeNames {
		if offset+len(name)+1 > len(fakeEntries) {
			break
		}
		copy(fakeEntries[offset:], name)
		offset += len(name) + 1
	}

	return append(data, fakeEntries...)
}

func readUint(data []byte, offset int, size int) uint64 {
	if offset+size > len(data) {
		return 0
	}
	switch size {
	case 4:
		return uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	case 8:
		return binary.LittleEndian.Uint64(data[offset : offset+8])
	default:
		return 0
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
