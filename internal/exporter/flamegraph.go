package exporter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/VladMinzatu/ebpf-profiler/internal/profiler"
	"github.com/VladMinzatu/ebpf-profiler/internal/symbolizer"
)

type StackSelection int

const (
	_ = iota
	User
	Kernel
	Both
)

func BuildFoldedStacks(samples []profiler.Sample, which StackSelection) map[string]uint64 {
	agg := make(map[string]uint64)
	for _, s := range samples {
		add := func(stack []symbolizer.Symbol) {
			if len(stack) == 0 {
				return
			}

			names := make([]string, 0, len(stack))
			for i := len(stack) - 1; i >= 0; i-- { // reverse order because flamegraphs expect root->leaf order
				name := stack[i].Name
				if name == "" {
					name = "<unknown>"
				}
				name = escapeFoldedName(name)
				names = append(names, name)
			}
			key := strings.Join(names, ";")
			agg[key] += s.Count
		}

		switch which {
		case User:
			add(s.UserStack)
		case Kernel:
			add(s.KernelStack)
		case Both:
			add(s.UserStack)
			add(s.KernelStack)
		}
	}
	return agg
}

func escapeFoldedName(name string) string {
	// semicolons separate frames and newlines separate lines. Replace them with safe characters.
	name = strings.ReplaceAll(name, ";", "_")  // frame separator in folded stacks format
	name = strings.ReplaceAll(name, "\n", " ") // line separator, duh
	name = strings.TrimSpace(name)
	if name == "" {
		return "<unknown>"
	}
	return name
}

func WriteFoldedStacksToFile(agg map[string]uint64, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	type kv struct {
		k string
		v uint64
	}
	var items []kv
	for k, v := range agg {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v == items[j].v {
			return items[i].k < items[j].k
		}
		return items[i].v > items[j].v
	})

	for _, it := range items {
		if _, err := fmt.Fprintf(f, "%s %d\n", it.k, it.v); err != nil {
			return err
		}
	}
	return nil
}
