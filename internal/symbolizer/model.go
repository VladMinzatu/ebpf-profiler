package symbolizer

type Symbol struct {
	Name string
	PC   uint64
}

type ProcMapsProvider interface {
	FindRegion(pc uint64) *MapRegion
	Refresh() error
}

type SymbolDataResolver interface {
	ResolvePC(pc uint64, slide uint64) (*Symbol, error)
}

type SymbolDataProvider interface {
	Get(path string) (SymbolDataResolver, error)
}
