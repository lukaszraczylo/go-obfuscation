//go:build darwin

package antidebug

func CheckHardwareBreakpoints() (bool, error) {
	return false, nil
}
