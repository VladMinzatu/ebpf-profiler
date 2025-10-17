# ebpf-profiler

## Build

The C code inside `./internal/ebpf/bpf` is used in the `go generate` step, which runs the `bpf2go` tool. So to build, run:
```
go generate ./internal/ebpf && go build
```
