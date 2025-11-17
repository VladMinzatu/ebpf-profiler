package exporter

import (
	"testing"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
	v1 "go.opentelemetry.io/proto/otlp/common/v1"
	profilespb "go.opentelemetry.io/proto/otlp/profiles/v1development"
	resourceV1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}
	return b
}

func TestBuildOltpProfile_Basic(t *testing.T) {
	sampleTS := time.Unix(10, 123456789)
	nowValue := uint64(9999999999)

	samples := []profiler.Sample{
		{
			Timestamp: sampleTS,
			UserStack: []symbolizer.Symbol{
				{Name: "foo", Addr: 0x1000, Offset: 0x10},
				{Name: "bar", Addr: 0x1100, Offset: 0x0},
			},
			KernelStack: nil,
			Count:       5,
		},
	}

	got := BuildOltpProfile(samples, func() uint64 { return nowValue })
	expectedStringTable := []string{"", "samples", "count", "foo", "bar"}
	expectedMappingTable := []*profilespb.Mapping{{}}
	expectedFunctionTable := []*profilespb.Function{
		{},
		{
			NameStrindex:       int32(3), // "foo"
			SystemNameStrindex: int32(3),
		},
		{
			NameStrindex:       int32(4), // "bar"
			SystemNameStrindex: int32(4),
		},
	}

	expectedLocationTable := []*profilespb.Location{
		{},
		{
			Address:      uint64(0x1000),
			MappingIndex: 0,
			Lines: []*profilespb.Line{
				{FunctionIndex: 1, Line: 0},
			},
		},
		{
			Address:      uint64(0x1100),
			MappingIndex: 0,
			Lines: []*profilespb.Line{
				{FunctionIndex: 2, Line: 0},
			},
		},
	}

	expectedStackTable := []*profilespb.Stack{
		{},
		{
			LocationIndices: []int32{1, 2},
		},
	}

	expectedSamples := []*profilespb.Sample{
		{
			StackIndex:         1,
			Values:             []int64{int64(5)},
			AttributeIndices:   []int32{},
			LinkIndex:          0,
			TimestampsUnixNano: []uint64{uint64(sampleTS.UnixNano())},
		},
	}

	expectedSampleType := &profilespb.ValueType{
		TypeStrindex: int32(1),
		UnitStrindex: int32(2),
	}

	expectedProfile := &profilespb.Profile{
		TimeUnixNano: nowValue,
		DurationNano: uint64(0),
		SampleType:   expectedSampleType,
		Samples:      expectedSamples,
	}

	expectedResourceProfiles := &profilespb.ResourceProfiles{
		Resource: &resourceV1.Resource{},
		ScopeProfiles: []*profilespb.ScopeProfiles{
			{
				Scope: &v1.InstrumentationScope{
					Name:    "ebpf-profiler",
					Version: "v1",
				},
				Profiles: []*profilespb.Profile{expectedProfile},
			},
		},
	}

	expectedDict := &profilespb.ProfilesDictionary{
		MappingTable:  expectedMappingTable,
		LocationTable: expectedLocationTable,
		FunctionTable: expectedFunctionTable,
		StackTable:    expectedStackTable,
		StringTable:   expectedStringTable,
	}

	expected := &profilespb.ProfilesData{
		ResourceProfiles: []*profilespb.ResourceProfiles{expectedResourceProfiles},
		Dictionary:       expectedDict,
	}

	if !proto.Equal(got, expected) {
		gotB := mustMarshal(t, got)
		wantB := mustMarshal(t, expected)
		t.Fatalf("ProfilesData proto mismatch\nGOT (len %d): %x\nWANT (len %d): %x", len(gotB), gotB, len(wantB), wantB)
	}
}

func TestBuildOltpProfile_ProtoEqual_CombinedStack(t *testing.T) {
	sampleTS := time.Unix(20, 0)
	nowValue := uint64(123456)

	samples := []profiler.Sample{
		{
			Timestamp: sampleTS,
			UserStack: []symbolizer.Symbol{
				{Name: "u1", Addr: 0x2000, Offset: 0},
				{Name: "u2", Addr: 0x2010, Offset: 0},
			},
			KernelStack: []symbolizer.Symbol{
				{Name: "k1", Addr: 0xffff0000, Offset: 0},
			},
			Count: 7,
		},
	}

	got := BuildOltpProfile(samples, func() uint64 { return nowValue })

	expectedStringTable := []string{"", "samples", "count", "u1", "u2", "k1"}
	expectedMappingTable := []*profilespb.Mapping{{}}
	expectedFunctionTable := []*profilespb.Function{
		{},
		{NameStrindex: int32(3), SystemNameStrindex: int32(3)},
		{NameStrindex: int32(4), SystemNameStrindex: int32(4)},
		{NameStrindex: int32(5), SystemNameStrindex: int32(5)},
	}

	expectedLocationTable := []*profilespb.Location{
		{},
		{Address: uint64(0x2000), MappingIndex: 0, Lines: []*profilespb.Line{{FunctionIndex: 1, Line: 0}}},
		{Address: uint64(0x2010), MappingIndex: 0, Lines: []*profilespb.Line{{FunctionIndex: 2, Line: 0}}},
		{Address: uint64(0xffff0000), MappingIndex: 0, Lines: []*profilespb.Line{{FunctionIndex: 3, Line: 0}}},
	}

	expectedStackTable := []*profilespb.Stack{
		{},
		{LocationIndices: []int32{1, 2, 3}},
	}

	expectedSamples := []*profilespb.Sample{
		{
			StackIndex:         1,
			Values:             []int64{int64(7)},
			AttributeIndices:   []int32{},
			LinkIndex:          0,
			TimestampsUnixNano: []uint64{uint64(sampleTS.UnixNano())},
		},
	}

	expectedSampleType := &profilespb.ValueType{TypeStrindex: int32(1), UnitStrindex: int32(2)}
	expectedProfile := &profilespb.Profile{
		TimeUnixNano: nowValue,
		DurationNano: uint64(0),
		SampleType:   expectedSampleType,
		Samples:      expectedSamples,
	}

	expectedResourceProfiles := &profilespb.ResourceProfiles{
		Resource: &resourceV1.Resource{},
		ScopeProfiles: []*profilespb.ScopeProfiles{
			{
				Scope: &v1.InstrumentationScope{Name: "ebpf-profiler", Version: "v1"},
				Profiles: []*profilespb.Profile{
					expectedProfile,
				},
			},
		},
	}

	expectedDict := &profilespb.ProfilesDictionary{
		MappingTable:  expectedMappingTable,
		LocationTable: expectedLocationTable,
		FunctionTable: expectedFunctionTable,
		StackTable:    expectedStackTable,
		StringTable:   expectedStringTable,
	}

	expected := &profilespb.ProfilesData{
		ResourceProfiles: []*profilespb.ResourceProfiles{expectedResourceProfiles},
		Dictionary:       expectedDict,
	}

	if !proto.Equal(got, expected) {
		gotB := mustMarshal(t, got)
		wantB := mustMarshal(t, expected)
		t.Fatalf("ProfilesData proto mismatch\nGOT (len %d): %x\nWANT (len %d): %x", len(gotB), gotB, len(wantB), wantB)
	}
}
