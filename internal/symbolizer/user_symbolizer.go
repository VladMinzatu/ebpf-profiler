package symbolizer

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Symbolizer struct {
	pid int
}

func NewSymbolizer(pid int) *Symbolizer {
	return &Symbolizer{pid: pid}
}

func (s *Symbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	regions, err := ReadProcMaps(s.pid)
	if err != nil {
		return nil, fmt.Errorf("symbolization failed due to failure to read proc maps: %v", err)
	}
	var symbols []Symbol
	for _, pc := range stack {
		r := regions.FindRegion(pc)
		if r == nil {
			slog.Warn("Did not find map region for PC", "pc", pc)
			continue
		}
		symbol, err := s.GetSymbol(s.pid, pc, r)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve symbol for pc=%d: %v", pc, err)
		}
		slog.Error(symbol.Name)
		symbols = append(symbols, *symbol)
	}
	return symbols, nil
}

func (s *Symbolizer) GetSymbol(pid int, pc uint64, m *MapRegion) (*Symbol, error) {
	ef, err := openELFForMapping(pid, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF for mapping: %v", err)
	}
	defer ef.Close()

	slide := computeSlide(ef, m)
	sym, err := ResolvePCFromELF(ef, pc, slide)
	if err != nil {
		return nil, fmt.Errorf("failed to load symbol from ELF: %v", err)
	}
	return sym, nil
}

func openELFForMapping(pid int, m *MapRegion) (*elf.File, error) {
	path := m.Path
	if path == "" || path == "[vdso]" || path == "[vsyscall]" || strings.HasPrefix(path, "[") {
		exe := fmt.Sprintf("/proc/%d/exe", pid)
		p, err := os.Readlink(exe)
		if err == nil {
			path = p
		} else {
			path = exe
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return ef, nil
}

func computeSlide(ef *elf.File, m *MapRegion) uint64 {
	// computes the difference between mapping start and ELF entry point or segment vaddr
	// Simple heuristic: look for PT_LOAD with lowest p_vaddr and compute slide = mapping.Start - p_vaddr
	var minVaddr uint64 = 0
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_LOAD {
			if minVaddr == 0 || prog.Vaddr < minVaddr {
				minVaddr = prog.Vaddr
			}
		}
	}
	var slide uint64 = 0
	if minVaddr != 0 {
		slide = m.Start - minVaddr
	}
	return slide
}
