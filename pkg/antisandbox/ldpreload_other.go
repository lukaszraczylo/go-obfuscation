//go:build !linux

package antisandbox

func CheckLDPreload() bool {
	return false
}

func CheckLdSoPreload() bool {
	return false
}

func UnsetInjectedEnv() error {
	return nil
}
