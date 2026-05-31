//go:build windows

package typewipe

import "fmt"

func wipePlatform(opts WipeOptions) error {
	return fmt.Errorf("typewipe: runtime wiping not supported on windows")
}
