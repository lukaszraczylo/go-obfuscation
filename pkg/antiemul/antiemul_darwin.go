//go:build darwin

package antiemul

func init() {
	platformCheck = func() bool {
		return checkTiming()
	}
}
