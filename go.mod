module github.com/VladMinzatu/ebpf-profiler

go 1.25.2

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.19.0
	github.com/google/pprof v0.0.0-20251007162407-5df77e3f7d1d
	go.opentelemetry.io/proto/otlp v1.9.0
	go.opentelemetry.io/proto/otlp/profiles/v1development v0.2.0
	golang.org/x/sys v0.35.0
)

require google.golang.org/protobuf v1.36.10 // indirect
