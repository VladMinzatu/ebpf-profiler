package symbolizer

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
)

type elfSymbolResolver struct {
	ef    *elf.File
	slide uint64
}

func (r *elfSymbolResolver) Resolve(pc uint64) (*Symbol, error) {
	syms := make([]elf.Symbol, 0)
	if section := r.ef.Section(".symtab"); section != nil {
		st, err := r.ef.Symbols()
		if err == nil {
			syms = append(syms, st...)
		}
	}
	if section := r.ef.Section(".dynsym"); section != nil {
		st, err := r.ef.DynamicSymbols()
		if err == nil {
			syms = append(syms, st...)
		}
	}
	if len(syms) == 0 {
		return nil, errors.New("no symbol tables available in ELF")
	}

	target := pc - r.slide
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

type dwarfSymbolResolver struct {
	ef    *elf.File
	slide uint64
}

func (r *dwarfSymbolResolver) Resolve(pc uint64) (*Symbol, error) {
	d, err := r.ef.DWARF()
	if err != nil {
		return nil, err
	}
	target := pc - r.slide

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

type goSymbolResolver struct {
	ef    *elf.File
	slide uint64
}

func (r *goSymbolResolver) Resolve(pc uint64) (*Symbol, error) {
	pcln := r.ef.Section(".gopclntab")
	if pcln == nil {
		return nil, errors.New("no .gopclntab section")
	}
	pclnData, err := pcln.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gopclntab: %v", err)
	}

	var symtabData []byte
	if symsec := r.ef.Section(".gosymtab"); symsec != nil {
		if data, err2 := symsec.Data(); err2 == nil {
			symtabData = data
		}
	}

	var textAddr uint64
	if text := r.ef.Section(".text"); text != nil {
		textAddr = text.Addr
	}
	lt := gosym.NewLineTable(pclnData, textAddr)
	// gosym.Table can be created with nil symtab; in that case only line lookups work sparsely.
	// However, PCToFunc still often works if names are in pclntab (Go embeds names there).
	tab, err := gosym.NewTable(symtabData, lt)
	if err != nil {
		return nil, err
	}

	target := pc - r.slide
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
