package symbolizer

type KernelSymbolizer struct {
}

func (s *KernelSymbolizer) Symbolize(stack []uint64) ([]Symbol, error) {
	return nil, nil
}
