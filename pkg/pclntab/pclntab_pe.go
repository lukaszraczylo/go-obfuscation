//go:build windows

package pclntab

import (
	"debug/pe"
	"fmt"
)

func readPclntabSection(binaryPath string) ([]byte, error) {
	f, err := pe.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("pclntab: failed to open PE: %w", err)
	}
	defer f.Close()

	sectionNames := []string{
		".gopclntab",
		"runtime.pclntab",
		"runtime.pclntab_v1",
	}

	for _, section := range f.Sections {
		for _, name := range sectionNames {
			if section.Name == name {
				data, err := section.Data()
				if err != nil {
					return nil, fmt.Errorf("pclntab: failed to read section %s: %w", name, err)
				}
				buf := make([]byte, len(data))
				copy(buf, data)
				return buf, nil
			}
		}
	}

	for _, section := range f.Sections {
		data, err := section.Data()
		if err != nil {
			continue
		}
		if len(data) >= 8 {
			for _, magic := range pclntabMagics {
				if len(data) >= len(magic) && bytesEqual(data[:len(magic)], magic) {
					buf := make([]byte, len(data))
					copy(buf, data)
					return buf, nil
				}
			}
		}
	}

	return nil, nil
}

func WriteCorruptedPclntab(binaryPath string, corrupted []byte, outputPath string) error {
	return fmt.Errorf("pclntab: offline PE patching not yet implemented; use runtime corruption instead")
}
