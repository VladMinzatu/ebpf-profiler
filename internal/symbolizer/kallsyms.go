package symbolizer

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
)

type KallsymsLoader interface {
	ReadLines() ([]string, error)
}

type KallsymsLoaderFS struct {
	loader *DataLoader
}

func NewKallsymsReader() *KallsymsLoaderFS {
	return &KallsymsLoaderFS{loader: &DataLoader{Path: "/proc/kallsyms"}}
}

func (p *KallsymsLoaderFS) ReadLines() ([]string, error) {
	return p.loader.ReadLines()
}

type kallsymsEntry struct {
	addr uint64
	name string
}

type KallsymsResolver struct {
	entries []kallsymsEntry
}

func InitKallsymsResolver(loader KallsymsLoader) (*KallsymsResolver, error) {
	lines, err := loader.ReadLines()
	if err != nil {
		return nil, err
	}
	entries := make([]kallsymsEntry, 0, 100000)
	for _, line := range lines {
		// Format: "ffffffff81000000 T _text" (addr type name [module])
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addrStr := parts[0]
		name := parts[2]
		addr, err := strconv.ParseUint(addrStr, 16, 64)
		if err != nil {
			continue
		}
		entries = append(entries, kallsymsEntry{addr: addr, name: name})
	}
	slog.Info("Loaded kallsyms for kernel symbolization", "entries", len(entries))

	// Sort by address to allow binary search
	sort.Slice(entries, func(i, j int) bool { return entries[i].addr < entries[j].addr })
	return &KallsymsResolver{entries: entries}, nil
}

func (r *KallsymsResolver) Resolve(pc uint64) (*Symbol, error) {
	if len(r.entries) == 0 {
		return nil, fmt.Errorf("empty kallsyms table")
	}
	// Find greatest entry.addr <= pc
	i := sort.Search(len(r.entries), func(i int) bool { return r.entries[i].addr > pc })
	if i == 0 {
		return nil, fmt.Errorf("no kernel symbol <= pc: 0x%x", pc)
	}
	entry := r.entries[i-1]
	return &Symbol{Name: entry.name, PC: pc - entry.addr}, nil
}
