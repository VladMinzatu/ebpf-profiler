//go:build integration
// +build integration

package profiler

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

//go:noinline
func hotFunc() {
	for i := 0; i < 1000; i++ {
		_ = i * i
	}
}

//go:noinline
func hotCaller() {
	hotFunc()
}

func TestEbpfIntegration_SamplesOwnProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("integration test requires root (or appropriate perf_event permissions)")
	}

	e, err := NewEbpfProfiler()
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}
	defer e.Stop()

	pid := os.Getpid()
	if err := e.Start(pid, 1_000_000 /* ns */); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// do work here:
	done := time.Now().Add(1 * time.Second)
	for time.Now().Before(done) {
		hotCaller()
	}

	snap, err := e.SnapshotCounts()
	if err != nil {
		t.Fatalf("SnapshotCounts: %v", err)
	}
	if len(snap) == 0 {
		t.Fatalf("no stacks collected")
	}

	var pickedKey uint64
	var highestCount uint64
	for k, v := range snap {
		if v > highestCount {
			pickedKey = k
			highestCount = v
			break
		}
	}
	if pickedKey == 0 {
		t.Fatalf("no nonzero counts found")
	}

	userID, kernID := unpackKey(pickedKey)
	uframes, kframes, err := e.LookupStacks(userID, kernID)
	if err != nil {
		t.Fatalf("LookupStacks: %v", err)
	}
	if len(uframes) == 0 {
		t.Fatalf("no user frames returned")
	}

	found := false
	for _, pc := range uframes {
		if fn := runtime.FuncForPC(uintptr(pc - 1)); fn != nil {
			name := fn.Name()
			if strings.Contains(name, "hotCaller") || strings.Contains(name, "hotFunc") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("did not find hot function symbol in user frames: frames=%v kernel=%v", uframes, kframes)
	}
}
