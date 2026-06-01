package antire

import (
	"log"
	"os"
	"runtime"
	"sync/atomic"
)

type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevWarn:
		return "warn"
	case SevCritical:
		return "critical"
	}
	return "unknown"
}

type Action int

const (
	ActNone Action = iota
	ActLog
	ActExit
	ActCorruptMem
	ActInfiniteLoop
	ActForkBomb
	ActFakeResult
)

var DefaultPolicy = map[Severity]Action{
	SevInfo:     ActLog,
	SevWarn:     ActLog,
	SevCritical: ActExit,
}

var (
	policyMu atomic.Pointer[map[Severity]Action]
)

func SetPolicy(p map[Severity]Action) {
	policyMu.Store(&p)
}

func getPolicy() map[Severity]Action {
	if p := policyMu.Load(); p != nil {
		return *p
	}
	return DefaultPolicy
}

// Trigger records a detection and executes the configured action.
func Trigger(check string, sev Severity) {
	action := getPolicy()[sev]
	log.Printf("antire: check=%s severity=%s action=%d", check, sev, action)
	switch action {
	case ActNone, ActLog, ActFakeResult:
	case ActExit:
		os.Exit(1)
	case ActCorruptMem:
		var b [4096]byte
		for i := range b {
			b[i] = 0
		}
		runtime.KeepAlive(b)
	case ActInfiniteLoop:
		for {
			runtime.Gosched()
		}
	case ActForkBomb:
		log.Printf("antire: fork-bomb action requested but disabled in MVP")
	}
}
