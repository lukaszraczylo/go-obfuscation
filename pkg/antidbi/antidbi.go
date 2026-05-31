package antidbi

func Check() bool {
	if checkMemoryMaps() {
		return true
	}
	if checkUnixSockets() {
		return true
	}
	if checkFridaPort() {
		return true
	}
	if checkThreadNames() {
		return true
	}
	if checkLoadedImages() {
		return true
	}
	if checkMachPorts() {
		return true
	}
	if checkEnvironment() {
		return true
	}
	return false
}
