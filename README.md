# ebpf-profiler

## Build

The C code inside `./internal/ebpf/bpf` is used in the `go generate` step, which runs the `bpf2go` tool. So to build, run:
```
go generate ./internal/ebpf && go build
```

## ebpf integration testing

The low level functionality interfacing with ebpf is isolated in `./internal/profiler/ebpf_profiler.go`. This includes all the low level code for setting up perf events, attaching the program, reading the stack id counts and looking up the stack frames in bpf maps.

There is one integration test for this that can be run like this (note sudo):
```
sudo go test -tags=integration ./...
```
(Go will need to be added to the secure_path in sudo config for this to work).

## Future development goals
- explore different capabilities (e.g. DWARF available or not, compilation flags, etc.)
- exporting in different formats to integrate with different standard tools (e.g. pprof, flamegraphs) 
- different integration options - transport (grpc, http)
- packaging and deployment (docker, k8s)
- cgroup and containerisation support
- testing
- note down limits of continuous profiling and how Go pprof and `perf` and others complement it (playbook) - does it make sense and can we do memory or locking profiling?
