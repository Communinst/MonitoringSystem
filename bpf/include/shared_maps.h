#pragma once
#include "../linux/vmlinux.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>

#define MAX_NODE_DNS_R_P_TTL 65536



struct hash_key{
    __u64 hash; // 8 - выравнивает по 8 - нет паддинга
    __u32 TXID; // 12 - выравнивает по ближайшему кратному 2 - нет
    struct src_ip_add src_ip; // 32
};
_Static_assert(sizeof(struct hash_key) == 32, "hash_key size mismatch");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct hash_key); 
    __type(value, __u64); // Timestamp
    __uint(max_entries, MAX_NODE_DNS_R_P_TTL);
} dns_hash_map SEC(".maps");