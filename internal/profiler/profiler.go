package profiler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/ebpf"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
)

type EbpfBackend interface {
	Start(targetPID int, samplingPeriodNs uint64) error
	Stop() error
	SnapshotCounts() (map[uint64]uint64, error)
	LookupStacks(userID uint32, kernID uint32) ([]uint64, []uint64, error)
}

type Symbolizer interface {
	Symbolize(userStack []uint64, kernelStack []uint64) ([]symbolizer.Symbol, []symbolizer.Symbol, error)
}

type Sample struct {
	Timestamp   time.Time
	UserStack   []symbolizer.Symbol
	KernelStack []symbolizer.Symbol
	Count       uint64
}

type Profiler struct {
	pid             int
	sampleHz        int
	collectInterval time.Duration
	backend         EbpfBackend
	symbolizer      Symbolizer

	samplesCh chan []Sample

	started bool
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewProfiler(pid int, sampleHz int, collectInterval time.Duration, backend EbpfBackend, symbolizer Symbolizer) (*Profiler, error) {
	if collectInterval <= 1*time.Millisecond {
		return nil, errors.New("invalid collectInterval; must be > 1ms")
	}
	if sampleHz <= 0 {
		return nil, errors.New("invalid sampleHz; must be > 0")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Profiler{pid: pid,
		sampleHz:        sampleHz,
		collectInterval: collectInterval,
		backend:         backend,
		symbolizer:      symbolizer,
		ctx:             ctx,
		cancel:          cancel,
		samplesCh:       make(chan []Sample, 1),
	}, nil
}

func (p *Profiler) Samples() <-chan []Sample { return p.samplesCh }

func (p *Profiler) Start() error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return errors.New("profiler already started")
	}
	p.started = true
	p.mu.Unlock()

	periodNs := uint64(1_000_000_000 / p.sampleHz)
	if err := p.backend.Start(p.pid, periodNs); err != nil {
		p.mu.Lock()
		p.started = false
		p.mu.Unlock()
		return err
	}

	p.wg.Add(1)
	go p.collector()

	return nil
}

func (p *Profiler) Stop() error {
	var stopErr error
	p.cancel()

	if err := p.backend.Stop(); err != nil {
		stopErr = err
	}

	// Wait for collector to exit
	p.wg.Wait()
	close(p.samplesCh)

	p.mu.Lock()
	p.started = false
	p.mu.Unlock()
	return stopErr
}

func (p *Profiler) collector() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.collectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case t := <-ticker.C:
			counts, err := p.backend.SnapshotCounts()
			if err != nil {
				slog.Warn("Failed to collect counts from ebpf map", "error", err)
				continue
			}

			var samples []Sample
			for key, cnt := range counts {
				userID, kernID := ebpf.UnpackKey(key)

				userPCs, kernPCs, err := p.backend.LookupStacks(userID, kernID)
				if err != nil {
					slog.Warn("Failed to resolve stack keys", "error", err)
					continue
				}

				userStack, kernStack, err := p.symbolizer.Symbolize(userPCs, kernPCs)
				if err != nil {
					slog.Warn("Failed to symbolize stacks", "error", err)
					continue
				}
				s := Sample{
					Timestamp:   t,
					UserStack:   userStack,
					KernelStack: kernStack,
					Count:       cnt,
				}
				samples = append(samples, s)
			}

			select {
			case p.samplesCh <- samples:
			default:
				slog.Warn("consumer wasn't ready, sample dropped")
			}
		}
	}
}
