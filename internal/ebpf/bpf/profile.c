//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACKS 16384
#define MAX_ENTRIES 65536

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACKS);
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");


SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx) {
    int flags = BPF_F_USER_STACK | BPF_F_REUSE_STACKID;
    int stackid = bpf_get_stackid(ctx, &stacks, flags);
    if (stackid < 0)
        return 0;

    u32 key = (u32)stackid;
    u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        *val += 1;
    } else {
        u64 init = 1;
        bpf_map_update_elem(&counts, &key, &init, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
