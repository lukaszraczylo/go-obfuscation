//go:build !linux && !darwin

package antidebug

func CheckHardwareBreakpoints() (bool, error) {
	return false, nil
}
