//go:build darwin

package pclntab

import (
	"debug/macho"
	"fmt"
)

func readPclntabSection(binaryPath string) ([]byte, error) {
	f, err := macho.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("pclntab: failed to open Mach-O: %w", err)
	}
	defer f.Close()

	sectionNames := []string{
		"__gopclntab",
		"__pclntab",
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
	return fmt.Errorf("pclntab: offline Mach-O patching not yet implemented; use runtime corruption instead")
}
