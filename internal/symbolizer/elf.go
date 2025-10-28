package symbolizer

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

type Symbol struct {
	Name string
	PC   uint64
}

func GetSymbol(pid int, pc uint64, m *MapRegion) (*Symbol, error) {
	ef, err := openELFForMapping(pid, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF for mapping: %v", err)
	}
	defer ef.Close()

	slide := computeSlide(ef, m)
	resolver := &elfSymbolResolver{ef: ef, slide: slide}
	sym, err := resolver.Resolve(pc)
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
