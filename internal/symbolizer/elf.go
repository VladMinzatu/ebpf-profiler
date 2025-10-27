package symbolizer

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"
)

type ElfSymbol struct {
	Name string
	PC   uint64
}

func GetRelevantSection(pid int, pc uint64, m *MapRegion) (*ElfSymbol, error) {
	ef, err := openELFForMapping(pid, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF for mapping: %v", err)
	}
	defer ef.Close()

	slide := computeSlide(ef, m)
	sym, err := symbolFromELF(ef, pc, slide)
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

func symbolFromELF(ef *elf.File, pc uint64, slide uint64) (*ElfSymbol, error) {
	syms := make([]elf.Symbol, 0)
	if section := ef.Section(".symtab"); section != nil {
		st, err := ef.Symbols()
		if err == nil {
			syms = append(syms, st...)
		}
	}
	if section := ef.Section(".dynsym"); section != nil {
		st, err := ef.DynamicSymbols()
		if err == nil {
			syms = append(syms, st...)
		}
	}
	if len(syms) == 0 {
		return nil, errors.New("no symbol tables available in ELF")
	}

	target := pc - slide
	var best *elf.Symbol
	for i := range syms {
		s := &syms[i]
		if s.Value == 0 {
			continue
		}
		if s.Value <= target {
			if best == nil || s.Value > best.Value {
				best = s
			}
		}
	}
	if best == nil {
		return nil, errors.New("no matching symbol")
	}
	return &ElfSymbol{Name: best.Name, PC: target - best.Value}, nil
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
