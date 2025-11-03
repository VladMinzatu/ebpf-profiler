package symbolizer

type Symbol struct {
	Name string
	PC   uint64
}

type SymbolResolver interface {
	ResolvePC(pc uint64, path string, slide uint64) (*Symbol, error)
}
