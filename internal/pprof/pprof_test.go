package pprof

import (
	"testing"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
	"github.com/google/pprof/profile"
)

func TestBuildPprofProfile_Empty(t *testing.T) {
	var samples []profiler.Sample
	p, err := BuildPprofProfile(samples, "samples", "count")
	if err != nil {
		t.Fatalf("BuildPprofProfile returned error for empty slice: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil profile")
	}
	if len(p.Sample) != 0 {
		t.Fatalf("expected 0 samples, got %d", len(p.Sample))
	}
}

func TestBuildPprofProfile_SingleUserSample(t *testing.T) {
	now := time.Now()
	sym := symbolizer.Symbol{Name: "foo", Addr: 0x1000}
	s := profiler.Sample{
		Timestamp:   now,
		UserStack:   []symbolizer.Symbol{sym},
		KernelStack: nil,
		Count:       3,
	}
	p, err := BuildPprofProfile([]profiler.Sample{s}, "samples", "count")
	if err != nil {
		t.Fatalf("BuildPprofProfile error: %v", err)
	}

	if len(p.Sample) != 1 {
		t.Fatalf("expected 1 pprof sample, got %d", len(p.Sample))
	}

	pp := p.Sample[0]
	if got := pp.Value[0]; got != int64(3) {
		t.Fatalf("unexpected sample Value: got %d want %d", got, 3)
	}
	if typ, ok := pp.Label["profile_type"]; !ok || len(typ) == 0 || typ[0] != "user" {
		t.Fatalf("expected profile_type=user label, got %v", pp.Label)
	}

	fn := findFuncByName(p, "foo")
	if fn == nil {
		t.Fatalf("function foo not found in profile.Function")
	}
	loc := findLocByAddr(p, 0x1000)
	if loc == nil {
		t.Fatalf("location for addr 0x1000 not found")
	}
	if len(loc.Line) == 0 || loc.Line[0].Function == nil || loc.Line[0].Function.Name != "foo" {
		t.Fatalf("location line does not reference function foo: %+v", loc.Line)
	}

	if p.TimeNanos != now.UnixNano() {
		t.Fatalf("unexpected TimeNanos: got %d want %d", p.TimeNanos, now.UnixNano())
	}
	if p.DurationNanos != 0 {
		t.Fatalf("expected DurationNanos 0 for single sample, got %d", p.DurationNanos)
	}
}

func TestBuildPprofProfile_UserAndKernelAndDedup(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(50 * time.Millisecond)

	symA := symbolizer.Symbol{Name: "A", Addr: 0x2000}
	symB := symbolizer.Symbol{Name: "B", Addr: 0x3000}

	samples := []profiler.Sample{
		{
			Timestamp:   t0,
			UserStack:   []symbolizer.Symbol{symA, symB}, // leaf A -> root B
			KernelStack: []symbolizer.Symbol{symB},
			Count:       1,
		},
		{
			Timestamp:   t1,
			UserStack:   []symbolizer.Symbol{symA},
			KernelStack: nil,
			Count:       2,
		},
	}

	p, err := BuildPprofProfile(samples, "samples", "count")
	if err != nil {
		t.Fatalf("BuildPprofProfile error: %v", err)
	}

	if len(p.Sample) != 3 {
		t.Fatalf("expected 3 pprof samples, got %d", len(p.Sample))
	}

	var userCount int64
	var kernelCount int64
	for _, s := range p.Sample {
		if typ, ok := s.Label["profile_type"]; ok && len(typ) > 0 {
			switch typ[0] {
			case "user":
				userCount += s.Value[0]
			case "kernel":
				kernelCount += s.Value[0]
			default:
				t.Fatalf("unexpected profile_type: %v", typ[0])
			}
		}
	}
	if userCount != 3 { // 1 + 2
		t.Fatalf("unexpected total userCount: got %d want %d", userCount, 3)
	}
	if kernelCount != 1 {
		t.Fatalf("unexpected total kernelCount: got %d want %d", kernelCount, 1)
	}

	if findFuncByName(p, "A") == nil {
		t.Fatalf("function A missing")
	}
	if findFuncByName(p, "B") == nil {
		t.Fatalf("function B missing")
	}
	if len(p.Function) != 2 {
		t.Fatalf("expected 2 functions (A,B), got %d", len(p.Function))
	}

	if findLocByAddr(p, 0x2000) == nil {
		t.Fatalf("location for 0x2000 missing")
	}
	if findLocByAddr(p, 0x3000) == nil {
		t.Fatalf("location for 0x3000 missing")
	}
	if len(p.Location) != 2 {
		t.Fatalf("expected 2 locations, got %d", len(p.Location))
	}

	if p.TimeNanos != t0.UnixNano() {
		t.Fatalf("unexpected TimeNanos: got %d want %d", p.TimeNanos, t0.UnixNano())
	}
	if p.DurationNanos != int64(t1.Sub(t0).Nanoseconds()) {
		t.Fatalf("unexpected DurationNanos: got %d want %d", p.DurationNanos, t1.Sub(t0).Nanoseconds())
	}
}

func findFuncByName(p *profile.Profile, name string) *profile.Function {
	for _, f := range p.Function {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func findLocByAddr(p *profile.Profile, addr uint64) *profile.Location {
	for _, l := range p.Location {
		if l.Address == addr {
			return l
		}
	}
	return nil
}
