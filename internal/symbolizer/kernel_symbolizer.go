package symbolizer

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
)

type KernelSymbolizer struct {
	symbolDataCache *SymbolDataCache
	vmlinuxPath     string
	kallsyms        *KallsymsResolver
	vmlinux         *VmlinuxResolver

	vmlinuxErr  error
	kallsymsErr error
}

func NewKernelSymbolizer(symbolDataCache *SymbolDataCache, vmlinuxPath string) *KernelSymbolizer {
	return &KernelSymbolizer{symbolDataCache: symbolDataCache, vmlinuxPath: vmlinuxPath}
}

func (s *KernelSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	// Lazy init: prefer vmlinux if provided, else fall back to /proc/kallsyms
	var resolver func(pc uint64) (*Symbol, error)

	if s.vmlinux == nil && s.vmlinuxPath != "" && s.vmlinuxErr == nil {
		vr, err := NewVmlinuxResolver(s.symbolDataCache, s.vmlinuxPath)
		if err != nil {
			slog.Error("Failed to load vmlinux", "path", s.vmlinuxPath, "error", err)
			s.vmlinuxErr = err
		} else {
			s.vmlinux = vr
		}
	}
	if s.vmlinux != nil {
		resolver = s.vmlinux.Resolve
	} else {
		if s.kallsyms == nil && s.kallsymsErr == nil {
			kr, err := NewKallsymsResolver()
			if err != nil {
				slog.Error("Failed to load kallsyms", "error", err)
				s.kallsymsErr = err
			} else {
				s.kallsyms = kr
			}
		}
		if s.kallsyms != nil {
			resolver = s.kallsyms.Resolve
		}
	}

	if resolver == nil {
		return nil, fmt.Errorf("no resolver for kernel symbolization could be loaded")
	}

	symbols := make([]Symbol, 0, len(stack))
	for _, pc := range stack {
		sym, err := resolver(pc)
		if err != nil {
			slog.Warn("Failed to resolve kernel symbol - skipping frame", "pc", hex.EncodeToString([]byte{byte(pc)}), "error", err)
			continue
		}
		symbols = append(symbols, *sym)
	}
	return symbols, nil
}

type VmlinuxResolver struct {
	symbolData SymbolDataResolver
}

func NewVmlinuxResolver(symbolDataCache *SymbolDataCache, path string) (*VmlinuxResolver, error) {
	symbolData, err := symbolDataCache.Get(path)
	if err != nil {
		return nil, err
	}
	return &VmlinuxResolver{symbolData: symbolData}, nil
}

func (r *VmlinuxResolver) Resolve(pc uint64) (*Symbol, error) {
	sym, err := r.symbolData.ResolvePC(pc, 0)
	if err != nil {
		return nil, err
	}
	return sym, nil
}

type kallsymsEntry struct {
	addr uint64
	name string
}

type KallsymsResolver struct {
	entries []kallsymsEntry
}

func NewKallsymsResolver() (*KallsymsResolver, error) {
	slog.Info("Initializing kallsyms symbolizer - reading /proc/kallsyms")
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	entries := make([]kallsymsEntry, 0, 100000)
	for s.Scan() {
		line := s.Text()
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

	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("reading /proc/kallsyms: %v", err)
	}
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
