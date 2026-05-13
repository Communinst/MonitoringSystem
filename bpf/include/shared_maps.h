#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_NODE_DNS_R_P_TTL 65536

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); 
    __type(value, __u64); // Timestamp
    __uint(max_entries, MAX_NODE_DNS_R_P_TTL);
} dns_hash_map SEC(".maps");