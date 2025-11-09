package pprof

import (
	"compress/gzip"
	"io"
	"sort"

	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
	"github.com/google/pprof/profile"
)

func BuildPprofProfile(samples []profiler.Sample, sampleTypeName, sampleTypeUnit string) (*profile.Profile, error) {
	if len(samples) == 0 {
		p := &profile.Profile{}
		return p, nil
	}

	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: sampleTypeName, Unit: sampleTypeUnit}},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
	}

	funcs := map[string]*profile.Function{}
	locMap := map[uint64]*profile.Location{}
	nextFuncID := uint64(1)
	nextLocID := uint64(1)

	addFunction := func(name string) *profile.Function {
		if f, ok := funcs[name]; ok {
			return f
		}
		fn := &profile.Function{
			ID:   nextFuncID,
			Name: name,
		}
		nextFuncID++
		funcs[name] = fn
		p.Function = append(p.Function, fn)
		return fn
	}

	addLocationFor := func(sym symbolizer.Symbol) *profile.Location {
		addr := sym.Addr
		if loc, ok := locMap[addr]; ok {
			return loc
		}
		fn := addFunction(sym.Name)
		loc := &profile.Location{
			ID:      nextLocID,
			Address: addr,
			Line:    []profile.Line{{Function: fn, Line: 0}},
		}
		nextLocID++
		locMap[addr] = loc
		p.Location = append(p.Location, loc)
		return loc
	}

	// for each sample -> up to 2 pprof samples (we separate user and kernel, which is more flexible for downstream)
	for _, s := range samples {
		emit := func(stack []symbolizer.Symbol, typ string) {
			if len(stack) == 0 {
				return
			}
			// pprof assumes stacks are in leaf-to-root order, i.e. stack[0] is leaf (innermost)
			locs := make([]*profile.Location, 0, len(stack))
			for _, sym := range stack {
				loc := addLocationFor(sym)
				locs = append(locs, loc)
			}

			val := int64(s.Count)
			pprofSample := &profile.Sample{
				Value:    []int64{val},
				Location: locs,
				Label:    map[string][]string{}, // TODO: we can add to this later
				NumLabel: map[string][]int64{},
			}

			pprofSample.Label["profile_type"] = []string{typ}
			p.Sample = append(p.Sample, pprofSample)
		}

		emit(s.UserStack, "user")
		emit(s.KernelStack, "kernel")
	}

	// p.StartTime / Duration: use first and last sample timestamps
	sort.Slice(samples, func(i, j int) bool { return samples[i].Timestamp.Before(samples[j].Timestamp) })
	start := samples[0].Timestamp
	end := samples[len(samples)-1].Timestamp
	p.TimeNanos = start.UnixNano()
	p.DurationNanos = end.Sub(start).Nanoseconds()

	// sort for deterministic output
	sort.Slice(p.Function, func(i, j int) bool { return p.Function[i].ID < p.Function[j].ID })
	sort.Slice(p.Location, func(i, j int) bool { return p.Location[i].ID < p.Location[j].ID })

	return p, nil
}

func WriteProfileGzip(p *profile.Profile, w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	return p.Write(gw)
}
