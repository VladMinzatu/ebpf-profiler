package symbolizer

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type MapRegion struct {
	Start, End uint64
	Offset     uint64
	Perms      string
	Path       string
}

type MapRegions struct {
	regions []MapRegion
}

type UserSymbolizer struct {
	symbolDataCache *SymbolDataCache
	pid             int
}

func NewUserSymbolizer(symbolDataCache *SymbolDataCache, pid int) *UserSymbolizer {
	return &UserSymbolizer{symbolDataCache: symbolDataCache, pid: pid}
}

func (s *UserSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
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
		symbols = append(symbols, *symbol)
	}
	return symbols, nil
}

func (s *UserSymbolizer) GetSymbol(pid int, pc uint64, m *MapRegion) (*Symbol, error) {
	ef, err := openELFForMapping(pid, m)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF for mapping: %v", err)
	}
	defer ef.Close()

	slide := computeSlide(ef, m)
	symbolData, err := s.symbolDataCache.Get(m.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get symbol data for path %s: %v", m.Path, err)
	}
	sym, err := symbolData.ResolvePC(pc, slide)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve PC: %v", err)
	}
	return sym, nil
}

func ReadProcMaps(pid int) (*MapRegions, error) {
	slog.Info("Reading proc maps for pid", "pid", pid)
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []MapRegion
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		entry, err := parseMapEntry(line)
		if err != nil {
			slog.Warn("Failed to parse entry in /proc/<pid>/map file", "pid", pid, "err", err)
			continue
		}
		regions = append(regions, entry)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return &MapRegions{regions: regions}, nil
}

func (m *MapRegions) FindRegion(ip uint64) *MapRegion {
	// TODO: maps should be in order so we could optimize to a binary search or use a tree
	for _, m := range m.regions {
		if ip >= m.Start && ip < m.End {
			return &m
		}
	}
	return nil
}

func parseMapEntry(line string) (MapRegion, error) {
	// example:
	// 55d4b2000000-55d4b2021000 r--p 00000000 08:01 131073 /usr/bin/myprog
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return MapRegion{}, fmt.Errorf("not enough fields fields: %d in line \"%s\"", len(parts), line)
	}
	addr := parts[0]
	perms := parts[1]
	off := parts[2]
	// pathname is optional and may be in parts[5:] - may contain spaces, mind you!
	var path string
	if len(parts) >= 6 {
		path = strings.Join(parts[5:], " ")
	}
	se := strings.SplitN(addr, "-", 2)
	start, err1 := strconv.ParseUint(se[0], 16, 64)
	end, err2 := strconv.ParseUint(se[1], 16, 64)
	offv, err3 := strconv.ParseUint(off, 16, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return MapRegion{}, fmt.Errorf("failed to parse numeric addresses in line %s", line)
	}
	return MapRegion{Start: start, End: end, Offset: offv, Perms: perms, Path: path}, nil
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
