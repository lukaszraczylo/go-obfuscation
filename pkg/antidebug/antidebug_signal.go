package antidebug

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

var signalTrapDetected bool

func checkSignalTrap() bool {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTRAP)

	signalTrapDetected = false
	go func() {
		select {
		case <-ch:
			signalTrapDetected = true
		case <-time.After(200 * time.Millisecond):
		}
	}()

	time.Sleep(10 * time.Millisecond)

	syscall.Kill(syscall.Getpid(), syscall.SIGTRAP)

	time.Sleep(250 * time.Millisecond)
	signal.Stop(ch)

	// If the handler received the signal, no debugger intercepted it.
	// If signalTrapDetected is false, a debugger caught the SIGTRAP.
	return !signalTrapDetected
}
