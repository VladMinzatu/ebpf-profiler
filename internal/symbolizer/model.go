package symbolizer

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
)

type Symbol struct {
	Name string
	PC   uint64
}

type SymbolData struct {
	ElfSymbols []elf.Symbol
	DwarfData  *dwarf.Data
	GoSymTab   *gosym.Table
	TextAddr   uint64
}

type ProcMapsProvider interface {
	FindRegion(pc uint64) *MapRegion
	Refresh() error
}

type SymbolDataProvider interface {
	Get(path string) (*SymbolData, error)
}
