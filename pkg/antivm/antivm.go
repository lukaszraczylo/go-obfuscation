package antivm

func Check() bool {
	if checkDMI() {
		return true
	}
	if checkMAC() {
		return true
	}
	if checkCPUID() {
		return true
	}
	if checkDisk() {
		return true
	}
	if checkPCI() {
		return true
	}
	if checkTiming() {
		return true
	}
	if checkSystemProfiler() {
		return true
	}
	if checkIOKit() {
		return true
	}
	if checkRegistry() {
		return true
	}
	if checkWMI() {
		return true
	}
	return false
}
