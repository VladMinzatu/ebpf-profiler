package profiler

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
)

func TestProfiler_StartStop_CallsBackend(t *testing.T) {
	f := &mockBackend{}
	sym := &mockSymbolizer{}
	p, err := NewProfiler(1234, 100, 20*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	f.mu.Lock()
	if !f.startCalled {
		f.mu.Unlock()
		t.Fatalf("backend.Start was not called")
	}
	if f.startArgs.targetPID != 1234 {
		t.Fatalf("unexpected target pid: got %d", f.startArgs.targetPID)
	}
	if f.startArgs.samplingPeriod == 0 {
		t.Fatalf("samplingPeriod not set")
	}
	f.mu.Unlock()

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	f.mu.Lock()
	if !f.stopCalled {
		f.mu.Unlock()
		t.Fatalf("backend.Stop was not called")
	}
	f.mu.Unlock()
}

func TestProfiler_CollectorEmitsSamples(t *testing.T) {
	userID := uint32(7)
	kernID := uint32(3)
	key := packKey(userID, kernID)

	f := &mockBackend{
		snapshots: []map[uint64]uint64{
			{key: 42},
		},
		stacks: map[uint32][]uint64{
			userID: {0x1000, 0x2000},
		},
	}

	sym := &mockSymbolizer{
		sMap: map[uint64]symbolizer.Symbol{
			0x1000: {Name: "f1", PC: 0},
			0x2000: {Name: "f2", PC: 0},
		},
	}

	p, err := NewProfiler(1, 100, 20*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	select {
	case samples := <-p.Samples():
		if len(samples) != 1 {
			t.Fatalf("expected 1 sample, got %d", len(samples))
		}
		s := samples[0]
		if s.Count != 42 {
			t.Fatalf("unexpected count: %d", s.Count)
		}
		if len(s.UserStack) != 2 || s.UserStack[0].Name != "f1" || s.UserStack[1].Name != "f2" {
			t.Fatalf("unexpected user stack: %#v", s.UserStack)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for sample")
	}
}

func TestProfiler_CollectorDropsWhenConsumerBusy(t *testing.T) {
	userID := uint32(5)
	key := packKey(userID, 0)
	f := &mockBackend{
		snapshots: []map[uint64]uint64{
			{key: 1},
		},
		stacks: map[uint32][]uint64{
			userID: {0x10},
		},
	}

	sym := &mockSymbolizer{
		sMap: map[uint64]symbolizer.Symbol{0x10: {Name: "f", PC: 0}},
	}

	p, err := NewProfiler(1, 100, 20*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// read the first sample to fill the buffer
	select {
	case <-p.Samples():
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for first sample")
	}

	// and now we fail to read samples for a while
	time.Sleep(3 * p.collectInterval)

	select {
	case <-p.Samples():
	default:
	}

	// stop should return without being blocked
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestProfiler_HandlesSnapshotError(t *testing.T) {
	f := &mockBackend{
		snapshotError: true,
	}

	sym := &mockSymbolizer{}
	p, err := NewProfiler(1, 100, 20*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	var samples []Sample
	select {
	case samples = <-p.Samples():
	case <-time.After(100 * time.Millisecond):
	}

	if samples != nil {
		t.Fatalf("failure to collect sample from ebpf map should have been handled gracefully - empty slice")
	}
}

func TestProfiler_StartNotIdempotent(t *testing.T) {
	f := &mockBackend{}
	sym := &mockSymbolizer{}
	p, err := NewProfiler(1, 100, 20*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start first time: %v", err)
	}

	if err := p.Start(); err == nil {
		t.Fatalf("expected error on second Start, got nil")
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestProfiler_HandlesLookupStacksError(t *testing.T) {
	userID := uint32(9)
	key := packKey(userID, 0)
	f := &mockBackend{
		snapshots: []map[uint64]uint64{{key: 5}},
		stacks:    nil,
	}
	sym := &mockSymbolizer{}
	p, err := NewProfiler(1, 100, 10*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	select {
	case samples := <-p.Samples():
		if len(samples) != 0 {
			t.Fatalf("expected 0 samples due to lookup error, got %d", len(samples))
		}
	case <-time.After(200 * time.Millisecond):
		// acceptable: send was skipped
	}
}

func TestProfiler_HandlesSymbolizerError(t *testing.T) {
	userID := uint32(11)
	key := packKey(userID, 0)
	f := &mockBackend{
		snapshots: []map[uint64]uint64{{key: 3}},
		stacks:    map[uint32][]uint64{userID: {0x1}},
	}
	sym := &mockSymbolizer{sErr: fmt.Errorf("boom")}
	p, err := NewProfiler(1, 100, 10*time.Millisecond, f, sym, sym)
	if err != nil {
		t.Fatalf("NewProfiler: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	select {
	case samples := <-p.Samples():
		if len(samples) != 0 {
			t.Fatalf("expected 0 samples due to symbolize error, got %d", len(samples))
		}
	case <-time.After(200 * time.Millisecond):
		// acceptable: send skipped due to the error
	}
}

type mockBackend struct {
	mu sync.Mutex

	startErr error
	stopErr  error

	snapshots     []map[uint64]uint64
	stacks        map[uint32][]uint64
	snapshotError bool

	startCalled bool
	stopCalled  bool
	startArgs   struct {
		targetPID      int
		samplingPeriod uint64
	}

	snapshotCalls int
}

func (f *mockBackend) Start(targetPID int, samplingPeriodNs uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalled = true
	f.startArgs.targetPID = targetPID
	f.startArgs.samplingPeriod = samplingPeriodNs
	return f.startErr
}

func (f *mockBackend) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalled = true
	return f.stopErr
}

func (f *mockBackend) SnapshotCounts() (map[uint64]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshotCalls++

	if f.snapshotError {
		return nil, fmt.Errorf("snapshotting counts failed to read from ebpf map")
	}

	if len(f.snapshots) == 0 {
		return map[uint64]uint64{}, nil
	}

	idx := f.snapshotCalls - 1
	if idx >= len(f.snapshots) {
		idx = len(f.snapshots) - 1
	}

	out := make(map[uint64]uint64, len(f.snapshots[idx]))
	for k, v := range f.snapshots[idx] {
		out[k] = v
	}
	return out, nil
}

func (f *mockBackend) LookupStacks(userID uint32, kernID uint32) ([]uint64, []uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.stacks == nil {
		return nil, nil, errors.New("no stacks configured")
	}
	sf, ok := f.stacks[userID]
	if !ok {
		return nil, nil, errors.New("stack not found")
	}

	uf := make([]uint64, len(sf))
	copy(uf, sf)
	return uf, nil, nil
}

type mockSymbolizer struct {
	sErr error
	sMap map[uint64]symbolizer.Symbol
}

func (m *mockSymbolizer) Symbolize(stack []uint64) ([]symbolizer.Symbol, error) {
	if m.sErr != nil {
		return nil, fmt.Errorf("symbolize error")
	}
	var s []symbolizer.Symbol
	for _, pc := range stack {
		if sym, ok := m.sMap[pc]; ok {
			s = append(s, sym)
		} else {
			s = append(s, symbolizer.Symbol{Name: fmt.Sprintf("0x%x", pc)})
		}
	}
	return s, nil
}

func packKey(user, kern uint32) uint64 {
	return (uint64(user) << 32) | uint64(kern)
}
