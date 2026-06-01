package antidebug

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	ssMu      sync.Mutex
	ssCount   int
	ssStop    chan struct{}
	ssChannel chan os.Signal
)

func InstallSingleStepDetector() error {
	ssMu.Lock()
	defer ssMu.Unlock()
	if ssStop != nil {
		return nil
	}
	ssStop = make(chan struct{})
	ssChannel = make(chan os.Signal, 16)
	signal.Notify(ssChannel, syscall.SIGTRAP)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ssStop:
				return
			case <-t.C:
				ssMu.Lock()
				ssCount = 0
				ssMu.Unlock()
			case <-ssChannel:
				ssMu.Lock()
				ssCount++
				ssMu.Unlock()
			}
		}
	}()
	return nil
}

func WasSingleStepped() bool {
	ssMu.Lock()
	defer ssMu.Unlock()
	return ssCount > 10
}

func UninstallSingleStepDetector() {
	ssMu.Lock()
	defer ssMu.Unlock()
	if ssStop == nil {
		return
	}
	close(ssStop)
	ssStop = nil
	if ssChannel != nil {
		signal.Stop(ssChannel)
		ssChannel = nil
	}
}
