package symbolizer

type Symbol struct {
	Name   string
	Addr   uint64 // absolute address of the symbol
	Offset uint64 // offset from function start
}
