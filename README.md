# ebpf-profiler

## Build

The C code inside `./internal/ebpf/bpf` is used in the `go generate` step, which runs the `bpf2go` tool. So to build, run:
```
go generate ./internal/ebpf && go build
```

## Future development goals
- explore different capabilities (e.g. DWARF available or not, compilation flags, etc.)
- exporting in different formats to integrate with different standard tools (e.g. pprof, flamegraphs) 
- different integration options - transport (grpc, http)
- packaging and deployment (docker, k8s)
- cgroup and containerisation support
- testing
- note down limits of continuous profiling and how Go pprof and `perf` and others complement it (playbook)
