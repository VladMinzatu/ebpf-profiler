package symbolizer

type Symbol struct {
	Name string
	PC   uint64
}

type MapRegion struct {
	Start, End uint64
	Offset     uint64
	Perms      string
	Path       string
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
