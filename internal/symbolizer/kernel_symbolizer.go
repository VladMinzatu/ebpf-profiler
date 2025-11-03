package symbolizer

import (
	"encoding/hex"
	"fmt"
	"log/slog"
)

type KernelSymbolizer struct {
	kallsymsLoader KallsymsLoader
	kallsyms       *KallsymsResolver
	kallsymsErr    error
}

func NewKernelSymbolizer(loader KallsymsLoader) *KernelSymbolizer {
	return &KernelSymbolizer{kallsymsLoader: loader}
}

func (s *KernelSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	if s.kallsyms == nil && s.kallsymsErr == nil {
		kr, err := InitKallsymsResolver(s.kallsymsLoader)
		if err != nil {
			slog.Error("Failed to load kallsyms", "error", err)
			s.kallsymsErr = err
		} else {
			s.kallsyms = kr
		}
	}

	if s.kallsyms == nil {
		return nil, fmt.Errorf("no resolver for kernel symbolization could be loaded")
	}

	symbols := make([]Symbol, 0, len(stack))
	for _, pc := range stack {
		sym, err := s.kallsyms.Resolve(pc)
		if err != nil {
			slog.Warn("Failed to resolve kernel symbol - skipping frame", "pc", hex.EncodeToString([]byte{byte(pc)}), "error", err)
			continue
		}
		symbols = append(symbols, *sym)
	}
	return symbols, nil
}
