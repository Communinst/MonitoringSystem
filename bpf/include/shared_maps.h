#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, struct dns_event); 
    __uint(max_entries, 1024);
} dns_hash_map SEC(".maps");