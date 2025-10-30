package symbolizer

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"errors"
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

func ReadProcMaps(pid int) (*MapRegions, error) {
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

func ResolvePCFromELF(ef *elf.File, pc uint64, slide uint64) (*Symbol, error) {
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
	return &Symbol{Name: best.Name, PC: target - best.Value}, nil
}

func ResolvePCFromDWARF(ef *elf.File, pc uint64, slide uint64) (*Symbol, error) {
	d, err := ef.DWARF()
	if err != nil {
		return nil, err
	}
	target := pc - slide

	rdr := d.Reader()
	for {
		ent, err := rdr.Next()
		if err != nil {
			return nil, err
		}
		if ent == nil {
			break
		}
		if ent.Tag != dwarf.TagSubprogram {
			continue
		}

		// Prefer explicit ranges API (handles DWARF v5 rnglists and v2/v4 ranges)
		inRange := false
		if ranges, err := d.Ranges(ent); err == nil && len(ranges) > 0 {
			for _, r := range ranges {
				if target >= r[0] && target < r[1] {
					inRange = true
					break
				}
			}
		} else {
			// Fallback to lowpc/highpc if present
			lowpcVal := ent.Val(dwarf.AttrLowpc)
			highpcVal := ent.Val(dwarf.AttrHighpc)
			var lowpc, highpc uint64
			if v, ok := lowpcVal.(uint64); ok {
				lowpc = v
			}
			switch v := highpcVal.(type) {
			case uint64:
				highpc = v
			case int64:
				if lowpc != 0 && v > 0 {
					highpc = lowpc + uint64(v)
				}
			}
			if lowpc != 0 && highpc != 0 && target >= lowpc && target < highpc {
				inRange = true
			}
		}
		if !inRange {
			continue
		}

		name := ""
		if v := ent.Val(dwarf.AttrLinkageName); v != nil {
			if s, ok := v.(string); ok && s != "" {
				name = s
			}
		}
		if name == "" {
			if v := ent.Val(dwarf.AttrName); v != nil {
				if s, ok := v.(string); ok {
					name = s
				}
			}
		}
		// Compute offset from entry if we have lowpc. Otherwise set 0
		var offset uint64
		if v := ent.Val(dwarf.AttrLowpc); v != nil {
			if low, ok := v.(uint64); ok && target >= low {
				offset = target - low
			}
		}
		if name == "" {
			return nil, errors.New("dwarf subprogram without name")
		}
		return &Symbol{Name: name, PC: offset}, nil
	}
	return nil, errors.New("pc not found in DWARF")
}

func ResolvePCFromGopclntab(ef *elf.File, pc uint64, slide uint64) (*Symbol, error) {
	pcln := ef.Section(".gopclntab")
	if pcln == nil {
		return nil, errors.New("no .gopclntab section")
	}
	pclnData, err := pcln.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gopclntab: %v", err)
	}

	var symtabData []byte
	if symsec := ef.Section(".gosymtab"); symsec != nil {
		if data, err2 := symsec.Data(); err2 == nil {
			symtabData = data
		}
	}

	var textAddr uint64
	if text := ef.Section(".text"); text != nil {
		textAddr = text.Addr
	}
	lt := gosym.NewLineTable(pclnData, textAddr)
	// gosym.Table can be created with nil symtab; in that case only line lookups work sparsely.
	// However, PCToFunc still often works if names are in pclntab (Go embeds names there).
	tab, err := gosym.NewTable(symtabData, lt)
	if err != nil {
		return nil, err
	}

	target := pc - slide
	fn := tab.PCToFunc(target)
	if fn == nil {
		return nil, errors.New("pc not found in gopclntab")
	}
	// Compute offset from function entry for parity with ELF path
	var offset uint64
	if target >= fn.Entry {
		offset = target - fn.Entry
	}
	return &Symbol{Name: fn.Name, PC: offset}, nil
}
