//go:build linux

package typewipe

import (
	"debug/elf"
	"fmt"
	"os"
	"syscall"
	"unsafe"
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
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("typewipe: cannot read /proc/self/exe: %w", err)
	}

	return wipeFromELF(self, opts)
}

func wipeFromELF(raw []byte, opts WipeOptions) error {
	f, err := elf.NewFile(newBytesReader(raw))
	if err != nil {
		return fmt.Errorf("typewipe: cannot parse ELF: %w", err)
	}

	var targets []wipeTarget

	if opts.WipeTypelink {
		sec := f.Section(".typelink")
		if sec != nil {
			targets = append(targets, wipeTarget{
				name:  ".typelink",
				addr:  uintptr(sec.Addr),
				size:  uintptr(sec.Size),
				xtype: wipeZero,
			})
		}
	}

	if opts.WipeItab {
		for _, name := range []string{".itablink", ".itab"} {
			sec := f.Section(name)
			if sec != nil {
				targets = append(targets, wipeTarget{
					name:  name,
					addr:  uintptr(sec.Addr),
					size:  uintptr(sec.Size),
					xtype: wipeXOR,
				})
				break
			}
		}
	}

	if opts.WipeTypeNames {
		for _, name := range []string{".gopclntab", "runtime.pclntab", "runtime.pclntab_v1"} {
			sec := f.Section(name)
			if sec == nil {
				continue
			}
			data, err := sec.Data()
			if err != nil {
				continue
			}
			nameStart, nameEnd := findTypeNameRegion(data)
			if nameStart > 0 && nameEnd > nameStart {
				targets = append(targets, wipeTarget{
					name:  name + ":names",
					addr:  uintptr(sec.Addr) + uintptr(nameStart),
					size:  uintptr(nameEnd - nameStart),
					xtype: wipeXOR,
				})
			}
			break
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

	if err := syscall.Mprotect(
		(*[1]byte)(unsafe.Pointer(baseAddr))[:protSize:protSize],
		syscall.PROT_READ|syscall.PROT_WRITE,
	); err != nil {
		return fmt.Errorf("mprotect RW failed: %w", err)
	}

	ptr := unsafe.Pointer(target.addr)
	sectionSlice := (*[1 << 30]byte)(ptr)[:target.size:target.size]

	switch target.xtype {
	case wipeZero:
		zeroSlice(sectionSlice)
	case wipeXOR:
		xorSlice(sectionSlice, key)
	}

	_ = syscall.Mprotect(
		(*[1]byte)(unsafe.Pointer(baseAddr))[:protSize:protSize],
		syscall.PROT_READ,
	)

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
