package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/ebpf"
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
	symbolDataCache := symbolizer.NewSymbolDataCache()
	userSymbolizer := symbolizer.NewUserSymbolizer(symbolDataCache, pid)
	kernelSymbolizer := symbolizer.NewKernelSymbolizer(symbolDataCache, "/boot/vmlinuz-6.8.0-86-generic")
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
	defer p.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		samples := p.Samples()
		for s := range samples {
			for _, sample := range s {
				fmt.Println(sample)
			}
		}
	}()

	go func() {
		done := time.Now().Add(10 * time.Second)
		for time.Now().Before(done) {
			hotCaller()
		}
	}()

	<-stop
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
