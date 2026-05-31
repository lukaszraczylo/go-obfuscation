//go:build darwin

package typewipe

import (
	"debug/macho"
	"fmt"
	"os"
	"syscall"
)

type wipeType int

const (
	wipeZero wipeType = iota
	wipeXOR
)

type wipeTarget struct {
	name  string
	addr  uintptr
	size  uintptr
	xtype wipeType
}

func wipePlatform(opts WipeOptions) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("typewipe: cannot determine executable: %w", err)
	}

	self, err := os.ReadFile(selfPath)
	if err != nil {
		return fmt.Errorf("typewipe: cannot read binary: %w", err)
	}

	return wipeFromMacho(self, opts)
}

func wipeFromMacho(raw []byte, opts WipeOptions) error {
	f, err := macho.NewFile(newBytesReader(raw))
	if err != nil {
		return fmt.Errorf("typewipe: cannot parse Mach-O: %w", err)
	}

	var targets []wipeTarget

	if opts.WipeTypelink {
		for _, sec := range f.Sections {
			if sec.Name == "__typelink" {
				targets = append(targets, wipeTarget{
					name:  "__typelink",
					addr:  uintptr(sec.Addr),
					size:  uintptr(sec.Size),
					xtype: wipeZero,
				})
				break
			}
		}
	}

	if opts.WipeItab {
		for _, sec := range f.Sections {
			if sec.Name == "__itablink" || sec.Name == "__itab" {
				targets = append(targets, wipeTarget{
					name:  sec.Name,
					addr:  uintptr(sec.Addr),
					size:  uintptr(sec.Size),
					xtype: wipeXOR,
				})
				break
			}
		}
	}

	if opts.WipeTypeNames {
		for _, sec := range f.Sections {
			if sec.Name == "__gopclntab" || sec.Name == "__pclntab" {
				data, err := sec.Data()
				if err != nil {
					continue
				}
				nameStart, nameEnd := findTypeNameRegion(data)
				if nameStart > 0 && nameEnd > nameStart {
					targets = append(targets, wipeTarget{
						name:  sec.Name + ":names",
						addr:  uintptr(sec.Addr) + uintptr(nameStart),
						size:  uintptr(nameEnd - nameStart),
						xtype: wipeXOR,
					})
				}
				break
			}
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("typewipe: no target sections found")
	}

	for _, t := range targets {
		if err := wipeSection(t, opts.Key); err != nil {
			return fmt.Errorf("typewipe: failed to wipe %s: %w", t.name, err)
		}
	}

	return nil
}

func wipeSection(target wipeTarget, key byte) error {
	pageSize := uintptr(syscall.Getpagesize())
	baseAddr := target.addr &^ (pageSize - 1)
	protSize := target.size + (target.addr - baseAddr)

	if err := mprotectRW(baseAddr, protSize); err != nil {
		return fmt.Errorf("mprotect RW failed: %w", err)
	}

	sectionSlice := ptrToSlice(target.addr, target.size)

	switch target.xtype {
	case wipeZero:
		zeroSlice(sectionSlice)
	case wipeXOR:
		xorSlice(sectionSlice, key)
	}

	_ = mprotectRO(baseAddr, protSize)

	return nil
}

func findTypeNameRegion(data []byte) (uint32, uint32) {
	magics := [][]byte{
		{0xF1, 0xFF, 0xFF, 0xFA},
		{0xF1, 0xFF, 0xFF, 0xF0},
		{0xF1, 0xFF, 0xFF, 0xF1},
	}

	if len(data) < 8 {
		return 0, 0
	}

	valid := false
	for _, m := range magics {
		if len(data) >= len(m) && bytesEqualLocal(data[:len(m)], m) {
			valid = true
			break
		}
	}
	if !valid {
		return 0, 0
	}

	ptrSize := int(data[6])
	if ptrSize != 4 && ptrSize != 8 {
		ptrSize = 8
	}

	isGo118 := bytesEqualLocal(data[:4], magics[2])

	if isGo118 {
		if len(data) < 16+4+6*ptrSize {
			return 0, 0
		}
		offset := 16 + 4
		offset += ptrSize // nfunc
		offset += ptrSize // nfiles
		offset += ptrSize // textStart
		funcnametab := readUintLocal(data, offset, ptrSize)

		nameStart := funcnametab
		if nameStart >= uint32(len(data)) {
			return 0, 0
		}

		nameEnd := findDoubleNull(data, nameStart)
		return nameStart, nameEnd
	}

	offset := 8 + 4 + 4
	if bytesEqualLocal(data[:4], magics[1]) {
		offset += 4
	}
	if offset+8 > len(data) {
		return 0, 0
	}

	nameStart := readUintLocal(data, offset, 4)
	if nameStart >= uint32(len(data)) {
		return 0, 0
	}

	nameEnd := findDoubleNull(data, nameStart)
	return nameStart, nameEnd
}

func findDoubleNull(data []byte, start uint32) uint32 {
	for i := start; i < uint32(len(data)); i++ {
		if data[i] == 0 && i+1 < uint32(len(data)) && data[i+1] == 0 {
			return i
		}
	}
	return uint32(len(data))
}

func readUintLocal(data []byte, offset int, size int) uint32 {
	if offset+size > len(data) {
		return 0
	}
	switch size {
	case 4:
		return uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	case 8:
		return uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	default:
		return 0
	}
}

func bytesEqualLocal(a, b []byte) bool {
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

type localBytesReader struct {
	data []byte
}

func newBytesReader(data []byte) *localBytesReader {
	return &localBytesReader{data: data}
}

func (r *localBytesReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || int(off) >= len(r.data) {
		return 0, fmt.Errorf("invalid offset")
	}
	n := copy(p, r.data[int(off):])
	if n < len(p) {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}
