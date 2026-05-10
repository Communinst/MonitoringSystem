#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>



// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 20); // 1 MB buffer for events (~4000 concurrent events capacity)
// } events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_event);
    __uint(max_entries, 1);
} scratchpad_map SEC(".maps");
