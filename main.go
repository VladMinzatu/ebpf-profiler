package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/ebpf"
	"github.com/VladMinzatu/ebpf-profiler/internal/exporter"
	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
)

func main() {
	backend, err := ebpf.NewEbpfBackend()
	if err != nil {
		slog.Error("Failed to initialise ebpf backend", "error", err)
		os.Exit(1)
	}

	pid := os.Getpid()
	procMapsProvider, _ := symbolizer.NewProcMaps(symbolizer.NewProcMapsReader(pid))
	symbolDataProvider := symbolizer.NewCachingSymbolResolver(pid, symbolizer.NewCascadingSymbolLoader(pid))
	userSymbolizer := symbolizer.NewUserSymbolizer(pid, procMapsProvider, symbolDataProvider)
	kernelSymbolizer := symbolizer.NewKernelSymbolizer(symbolizer.NewKallsymsReader())
	p, err := profiler.NewProfiler(pid, 1000_000, 1*time.Second, backend, userSymbolizer, kernelSymbolizer)
	if err != nil {
		slog.Error("Failed to initialise profiler", "error", err)
		os.Exit(1)
	}

	err = p.Start()
	if err != nil {
		slog.Error("Failed to start profiler", "error", err)
		os.Exit(1)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	var writePprof sync.WaitGroup

	writePprof.Add(1)
	go func() {
		defer writePprof.Done()
		var collectedSamples []profiler.Sample
		samples := p.Samples()
		for s := range samples {
			for _, sample := range s {
				collectedSamples = append(collectedSamples, sample)
			}
		}
		prof, err := exporter.BuildPprofProfile(collectedSamples, "cpu", "nanoseconds")
		if err != nil {
			slog.Error("Failed to build pprof Profile from the collected samples")
			return
		}

		err = exporter.WriteProfile(prof, "cpu-profile.pb")
		if err != nil {
			slog.Error("Failed to create output file for profile")
			return
		}
	}()

	go func() {
		done := time.Now().Add(10 * time.Second)
		for time.Now().Before(done) {
			hotCaller()
		}
	}()

	<-stop
	p.Stop() // stop the profiler - should close the samples channel

	writePprof.Wait()
}

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
