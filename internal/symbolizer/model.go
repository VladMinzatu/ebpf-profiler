package symbolizer

type Symbol struct {
	Name string
	PC   uint64
}

type SymbolResolver interface {
	ResolvePC(path string, pc uint64, slide uint64) (*Symbol, error)
}
