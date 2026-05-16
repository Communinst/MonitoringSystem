#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_NODE_DNS_R_P_TTL 65536


struct hash_key{
    __u64 hash; // 8 - выравнивает по 8 - нет паддинга
    __u16 TXID; // 10 - выравнивает по ближайшему кратному 2 - нет
    __u16 ip_v; // 12 - выравнивает по ближайшему кратному 2 - нет
    union { // 16 - выравнивание по 4 - нет
        __be32 ipv4; 
        __be32 ipv6[4]; 
    } ip;
    // 28 + 4 паддинга. Нужно явно занулять
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct hash_key); 
    __type(value, __u64); // Timestamp
    __uint(max_entries, MAX_NODE_DNS_R_P_TTL);
} dns_hash_map SEC(".maps");