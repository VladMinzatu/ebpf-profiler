package symbolizer

import (
	"bufio"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
)

type KernelSymbolizer struct {
	vmlinuxPath string
	kallsyms    *KallsymsResolver
	vmlinux     *VmlinuxResolver
}

func NewKernelSymbolizer(vmlinuxPath string) *KernelSymbolizer {
	return &KernelSymbolizer{vmlinuxPath: vmlinuxPath}
}

func (s *KernelSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	// Lazy init: prefer vmlinux if provided, else fall back to /proc/kallsyms
	var resolver func(pc uint64) (*Symbol, error)

	if s.vmlinux == nil && s.vmlinuxPath != "" {
		if vr, err := NewVmlinuxResolver(s.vmlinuxPath); err == nil {
			s.vmlinux = vr
		}
	}
	if s.vmlinux != nil {
		resolver = s.vmlinux.Resolve
	} else {
		if s.kallsyms == nil {
			if kr, err := NewKallsymsResolver(); err == nil {
				s.kallsyms = kr
			}
		}
		if s.kallsyms != nil {
			resolver = s.kallsyms.Resolve
		}
	}

	if resolver == nil {
		return nil, nil
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
	ef    *elf.File
	slide uint64
}

func NewVmlinuxResolver(path string) (*VmlinuxResolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	// TODO: We keep the file open via ef to allow section reads; perhaps close through method in the future if needed
	return &VmlinuxResolver{ef: ef, slide: 0}, nil
}

func (r *VmlinuxResolver) Resolve(pc uint64) (*Symbol, error) {
	if r.ef == nil {
		return nil, fmt.Errorf("vmlinux ELF not initialized")
	}
	// Try DWARF first, though rare to have it for kernel build - fall back to elf
	if sym, err := ResolvePCFromDWARF(r.ef, pc, r.slide); err == nil {
		return sym, nil
	}
	if sym, err := ResolvePCFromELF(r.ef, pc, r.slide); err == nil {
		return sym, nil
	}
	return nil, fmt.Errorf("kernel pc not found in vmlinux: 0x%x", pc)
}

type kallsymsEntry struct {
	addr uint64
	name string
}

type KallsymsResolver struct {
	entries []kallsymsEntry
}

func NewKallsymsResolver() (*KallsymsResolver, error) {
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
