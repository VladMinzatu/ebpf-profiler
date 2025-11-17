package exporter

import (
	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
	v1 "go.opentelemetry.io/proto/otlp/common/v1"
	profilespb "go.opentelemetry.io/proto/otlp/profiles/v1development"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
)

type NowFunc func() uint64 // produces unix nsec

func BuildOltpProfile(samples []profiler.Sample, now NowFunc) *profilespb.ProfilesData {
	nowNsec := now()
	stringTable := []string{""}
	mappingTable := []*profilespb.Mapping{{}}
	locationTable := []*profilespb.Location{{}}
	functionTable := []*profilespb.Function{{}}
	stackTable := []*profilespb.Stack{{}}

	defaultMappingIdx := 0
	profileSamples := make([]*profilespb.Sample, 0, len(samples))

	sampleType := &profilespb.ValueType{
		TypeStrindex: strIndex(&stringTable, "samples"),
		UnitStrindex: strIndex(&stringTable, "count"),
	}

	buildStack := func(symbols []symbolizer.Symbol) int32 {
		locIndices := make([]int32, 0, len(symbols))
		for _, sym := range symbols {
			funcNameIdx := strIndex(&stringTable, sym.Name)
			fn := &profilespb.Function{
				NameStrindex:       funcNameIdx,
				SystemNameStrindex: funcNameIdx,
			}
			functionTable = append(functionTable, fn)
			fnIdx := int32(len(functionTable) - 1)

			loc := &profilespb.Location{
				Address:      sym.Addr,
				MappingIndex: int32(defaultMappingIdx),
				Lines: []*profilespb.Line{
					{
						FunctionIndex: fnIdx,
						Line:          0,
					},
				},
			}
			locationTable = append(locationTable, loc)
			locIdx := int32(len(locationTable) - 1)
			locIndices = append(locIndices, locIdx)
		}

		stack := &profilespb.Stack{LocationIndices: locIndices}
		stackTable = append(stackTable, stack)
		return int32(len(stackTable) - 1)
	}

	for _, s := range samples {
		// we build a combined stack: user frames (leaf-first) then kernel frames (leaf-first)
		var symStack []symbolizer.Symbol
		if len(s.UserStack) == 0 && len(s.KernelStack) == 0 {
			continue
		}

		symStack = make([]symbolizer.Symbol, 0, len(s.UserStack)+len(s.KernelStack))
		if len(s.UserStack) > 0 {
			symStack = append(symStack, s.UserStack...)
		}
		if len(s.KernelStack) > 0 {
			symStack = append(symStack, s.KernelStack...)
		}

		stackIdx := buildStack(symStack)

		pbSample := &profilespb.Sample{
			StackIndex:         stackIdx,
			Values:             []int64{int64(s.Count)},
			AttributeIndices:   []int32{},
			LinkIndex:          0,
			TimestampsUnixNano: []uint64{uint64(s.Timestamp.UnixNano())},
		}
		profileSamples = append(profileSamples, pbSample)
	}

	profile := &profilespb.Profile{
		TimeUnixNano: nowNsec,
		DurationNano: uint64(0),
		SampleType:   sampleType,
		Samples:      profileSamples,
	}

	resource := &resourceV1.Resource{}
	resourceProfiles := &profilespb.ResourceProfiles{
		Resource: resource, // TODO add attributes
		ScopeProfiles: []*profilespb.ScopeProfiles{
			{
				Scope: &v1.InstrumentationScope{
					Name:    "ebpf-profiler",
					Version: "v1",
				},
				Profiles: []*profilespb.Profile{profile},
			},
		},
	}

	dictionary := &profilespb.ProfilesDictionary{
		MappingTable:  mappingTable,
		LocationTable: locationTable,
		FunctionTable: functionTable,
		StackTable:    stackTable,
		StringTable:   stringTable,
	}

	return &profilespb.ProfilesData{
		ResourceProfiles: []*profilespb.ResourceProfiles{resourceProfiles},
		Dictionary:       dictionary,
	}
}

func strIndex(table *[]string, s string) int32 {
	for i, v := range *table {
		if v == s {
			return int32(i)
		}
	}
	*table = append(*table, s)
	return int32(len(*table) - 1)
}
