package symbolizer

type Symbol struct {
	Name string
	PC   uint64
}

type SymbolDataResolver interface {
	ResolvePC(pc uint64, slide uint64) (*Symbol, error)
}

type SymbolDataProvider interface {
	Get(path string) (SymbolDataResolver, error)
}
