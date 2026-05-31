//go:build windows

package pclntab

import "fmt"

func runtimeCorrupt(binaryPath string, key byte) error {
	return fmt.Errorf("pclntab: runtime corruption not supported on windows")
}
