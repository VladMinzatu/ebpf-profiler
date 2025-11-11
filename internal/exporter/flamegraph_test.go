package exporter

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
)

func TestBuildFoldedStacks_AggregationAndOrder(t *testing.T) {
	now := time.Now()
	s1 := profiler.Sample{
		Timestamp: now,
		UserStack: []symbolizer.Symbol{
			{Name: "A", Addr: 0x100},
			{Name: "B", Addr: 0x200},
		},
		Count: 1,
	}
	s2 := profiler.Sample{
		Timestamp: now.Add(time.Millisecond),
		UserStack: []symbolizer.Symbol{
			{Name: "A", Addr: 0x100},
			{Name: "B", Addr: 0x200},
		},
		Count: 2,
	}
	agg := BuildFoldedStacks([]profiler.Sample{s1, s2}, User)
	if len(agg) != 1 {
		t.Fatalf("expected 1 aggregated entry, got %d", len(agg))
	}

	var key string
	for k := range agg {
		key = k
	}
	if key != "B;A" {
		t.Fatalf("unexpected folded key: %q (want B;A)", key)
	}
	if agg[key] != 3 {
		t.Fatalf("unexpected aggregated count: %d (want 3)", agg[key])
	}
}

func TestBuildFoldedStacks_Escaping(t *testing.T) {
	now := time.Now()
	s := profiler.Sample{
		Timestamp: now,
		UserStack: []symbolizer.Symbol{
			{Name: "Leaf;Name", Addr: 0x10},
			{Name: "Root\nName", Addr: 0x20},
		},
		Count: 1,
	}
	agg := BuildFoldedStacks([]profiler.Sample{s}, User)
	if len(agg) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(agg))
	}
	for k := range agg {
		if strings.Contains(k, ";") {
			parts := strings.Split(k, ";")
			if strings.Contains(parts[0], ";") || strings.Contains(parts[1], ";") {
				t.Fatalf("internal semicolon not escaped in %q", k)
			}
		}
	}
}

func TestWriteFoldedStacksToFile(t *testing.T) {
	agg := map[string]uint64{
		"root;leaf": 10,
		"r;l":       5,
	}
	tmp := t.TempDir() + "/folded.txt"
	if err := WriteFoldedStacksToFile(agg, tmp); err != nil {
		t.Fatalf("WriteFoldedStacksToFile failed: %v", err)
	}
	f, err := os.Open(tmp)
	if err != nil {
		t.Fatalf("open tmp file: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	for _, ln := range lines {
		parts := strings.SplitN(ln, " ", 2)
		if len(parts) != 2 {
			t.Fatalf("bad folded line format: %q", ln)
		}
		if strings.TrimSpace(parts[0]) == "" {
			t.Fatalf("empty stack in line: %q", ln)
		}
	}
}
