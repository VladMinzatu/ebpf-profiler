package profiler

//go:generate bash -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
//go:generate go tool bpf2go -tags linux profile bpf/profile.c
