package symbolizer

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// use this interface to resolve symbols from ELF files
type SymbolResolver interface {
	ResolvePC(path string, pc uint64, slide uint64) (*Symbol, error)
}

type SymbolLoader interface {
	LoadFrom(path string) (internalSymbolResolver, error)
}

// The standard SymbolResolver implementation that decorates concrete resolvers that rely on different symbols, and adds caching
type CachingSymbolResolver struct {
	// TODO: we lazy load and cache symbols without any LRU eviction - we should add it in the future
	cache        map[string]internalSymbolResolver
	symbolLoader SymbolLoader
	mu           sync.RWMutex
	pid          int
}

type internalSymbolResolver interface {
	ResolvePC(pc uint64, slide uint64) (*Symbol, error)
}

func NewCachingSymbolResolver(pid int) *CachingSymbolResolver {
	return &CachingSymbolResolver{pid: pid, cache: make(map[string]internalSymbolResolver)}
}

func (c *CachingSymbolResolver) ResolvePC(path string, pc uint64, slide uint64) (*Symbol, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if resolver, ok := c.cache[path]; ok {
		return resolver.ResolvePC(pc, slide)
	}
	resolver, err := c.symbolLoader.LoadFrom(path)
	if err != nil {
		return nil, err
	}
	c.cache[path] = resolver
	return resolver.ResolvePC(pc, slide)
}

func (c *CachingSymbolResolver) loadSymbolData(path string) (internalSymbolResolver, error) {
	data := &SymbolData{}
	elfSymbols, err := readElfSymbols(c.pid, path)
	if err != nil {
		return nil, err
	}
	data.ElfSymbols = elfSymbols

	dwarfData, err := readDwarfData(c.pid, path)
	if err != nil {
		slog.Info("Dwarf data not available", "path", path, "error", err)
	}
	data.DwarfData = dwarfData

	goSymTab, err := readGoSymbolTable(c.pid, path)
	if err != nil {
		slog.Info("Go symbol table not available", "path", path, "error", err)
	}
	data.GoSymTab = goSymTab
	c.cache[path] = data
	return data, nil
}

func (d *SymbolData) ResolvePC(pc uint64, slide uint64) (*Symbol, error) {
	if d.GoSymTab != nil {
		return d.resolvePCFromGoSymbolTable(pc, slide)
	}
	if d.DwarfData != nil {
		return d.resolvePCFromDwarfData(pc, slide)
	}
	if d.ElfSymbols != nil {
		return d.resolvePCFromElfSymbols(pc, slide)
	}
	return nil, errors.New("no symbol data available")
}

func (d *SymbolData) resolvePCFromGoSymbolTable(pc uint64, slide uint64) (*Symbol, error) {
	slog.Debug("Resolving PC from Go symbol table", "pc", pc, "slide", slide)

	target := pc - slide
	fn := d.GoSymTab.PCToFunc(target)
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

func (d *SymbolData) resolvePCFromDwarfData(pc uint64, slide uint64) (*Symbol, error) {
	slog.Debug("Resolving PC from DWARF data", "pc", pc, "slide", slide)
	target := pc - slide

	rdr := d.DwarfData.Reader()
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
		if ranges, err := d.DwarfData.Ranges(ent); err == nil && len(ranges) > 0 {
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

func (d *SymbolData) resolvePCFromElfSymbols(pc uint64, slide uint64) (*Symbol, error) {
	slog.Debug("Resolving PC from ELF symbols", "pc", pc, "slide", slide)
	target := pc - slide
	var best *elf.Symbol
	for _, s := range d.ElfSymbols {
		if s.Value == 0 {
			continue
		}
		if s.Value <= target {
			if best == nil || s.Value > best.Value {
				best = &s
			}
		}
	}
	if best == nil {
		return nil, errors.New("no matching symbol")
	}
	return &Symbol{Name: best.Name, PC: target - best.Value}, nil
}

func readElfSymbols(pid int, path string) ([]elf.Symbol, error) {
	slog.Info("Loading ELF symbols", "path", path)
	ef, err := openELF(pid, path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

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
	return syms, nil
}

func readDwarfData(pid int, path string) (*dwarf.Data, error) {
	slog.Info("Loading DWARF data", "path", path)
	ef, err := openELF(pid, path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	dwarfData, err := ef.DWARF()
	if err != nil {
		return nil, err
	}
	return dwarfData, nil
}

func readGoSymbolTable(pid int, path string) (*gosym.Table, error) {
	slog.Info("Loading Go line table", "path", path)
	ef, err := openELF(pid, path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

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
	return tab, nil
}

func openELF(pid int, path string) (*elf.File, error) {
	if path == "" || path == "[vdso]" || path == "[vsyscall]" || strings.HasPrefix(path, "[") {
		exe := fmt.Sprintf("/proc/%d/exe", pid)
		p, err := os.Readlink(exe)
		if err == nil {
			path = p
		} else {
			path = exe
		}
	}
	ef, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return ef, nil
}
