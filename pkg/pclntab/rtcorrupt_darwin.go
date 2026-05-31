//go:build darwin

package pclntab

import (
	"debug/macho"
	"fmt"
	"os"
	"syscall"
)

func runtimeCorrupt(binaryPath string, key byte) error {
	self, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("pclntab: cannot read binary: %w", err)
	}

	f, err := macho.NewFile(bytesReader(self))
	if err != nil {
		return fmt.Errorf("pclntab: cannot parse Mach-O from memory: %w", err)
	}

	sectionData, sectionAddr, sectionSize, err := findPclntabMacho(f)
	if err != nil {
		return err
	}

	nameStart, nameEnd := findMemoryNameRegion(sectionData)
	if nameStart == 0 || nameEnd <= nameStart {
		return fmt.Errorf("pclntab: could not locate name region")
	}

	pageSize := syscall.Getpagesize()
	baseAddr := sectionAddr &^ uintptr(pageSize-1)
	protSize := sectionSize + (sectionAddr - baseAddr)

	if err := mprotectRW(baseAddr, protSize); err != nil {
		return fmt.Errorf("pclntab: mprotect failed: %w", err)
	}

	nameSlice := ptrToSlice(sectionAddr+uintptr(nameStart), uintptr(nameEnd-nameStart))
	for i := range nameSlice {
		if nameSlice[i] != 0 {
			nameSlice[i] ^= key
		}
	}

	mprotectRO(baseAddr, protSize)
	return nil
}

func findPclntabMacho(f *macho.File) ([]byte, uintptr, uintptr, error) {
	sectionNames := []string{
		"__gopclntab",
		"__pclntab",
	}

	for _, sec := range f.Sections {
		for _, name := range sectionNames {
			if sec.Name == name {
				data, err := sec.Data()
				if err != nil {
					continue
				}
				buf := make([]byte, len(data))
				copy(buf, data)
				return buf, uintptr(sec.Addr), uintptr(sec.Size), nil
			}
		}
	}

	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if len(data) >= 8 {
			for _, magic := range pclntabMagics {
				if len(data) >= len(magic) && bytesEqual(data[:len(magic)], magic) {
					buf := make([]byte, len(data))
					copy(buf, data)
					return buf, uintptr(sec.Addr), uintptr(sec.Size), nil
				}
			}
		}
	}

	return nil, 0, 0, fmt.Errorf("pclntab: __gopclntab section not found in memory")
}

func findMemoryNameRegion(data []byte) (uint32, uint32) {
	tab := &pclntabParser{data: data}
	if err := tab.parse(); err != nil {
		return 0, 0
	}
	return findNameRegion(tab)
}

type bytesReaderWrapper struct {
	data []byte
}

func bytesReader(data []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: data}
}

func (r *bytesReaderWrapper) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) >= len(r.data) {
		return 0, fmt.Errorf("invalid offset")
	}
	n := copy(p, r.data[int(off):])
	if n < len(p) {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}
