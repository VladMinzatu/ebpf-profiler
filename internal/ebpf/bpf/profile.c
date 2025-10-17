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
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");


SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx) {
    int kernel_flags = BPF_F_REUSE_STACKID;       
    int user_flags = BPF_F_USER_STACK | BPF_F_REUSE_STACKID;

    int kernel_id = bpf_get_stackid(ctx, &stacks, kernel_flags);
    int user_id = bpf_get_stackid(ctx, &stacks, user_flags);

    if (kernel_id < 0 && user_id < 0) // either might still be negative, though
        return 0;

    /* normalize negatives to 0xffffffff to keep a stable 32-bit slot, or handle errors specially */
    u32 k = (kernel_id < 0) ? (u32)0xFFFFFFFF : (u32)kernel_id;
    u32 u = (user_id < 0) ? (u32)0xFFFFFFFF : (u32)user_id;

    u64 key = ((u64)u << 32) | (u64)k;

    u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        *val += 1; // safe, because it's a per-CPU map
    } else {
        u64 init = 1;
        bpf_map_update_elem(&counts, &key, &init, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
