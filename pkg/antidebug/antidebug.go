package antidebug

func Check() error {
	if err := checkPtrace(); err != nil {
		return err
	}

	if err := disableCoreDump(); err != nil {
		return err
	}

	if err := checkTiming(); err != nil {
		return err
	}

	if err := checkEnv(); err != nil {
		return err
	}

	if err := checkParentProcess(); err != nil {
		return err
	}

	if err := CheckHooks(); err != nil {
		return err
	}

	return nil
}
