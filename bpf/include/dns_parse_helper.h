#pragma once
#include "../linux/vmlinux.h"
#include "../linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "./dns_parse.h"



// static __always_inline u64 hash_dns_name(const struct dns_event *temp_event) {
//     u64 hash = 0xcbf29ce484222325ULL;
//     u64 prime = 0x100000001b3ULL;
    
//     // Верификатор разрешит это, так как он знает размер value в PERCPU карте
//     #pragma unroll
//     for (int i = 0; i < MAX_QNAME_LEN; i++) {
//         if (temp_event->qname[i] == '\0') {
//             break;
//         }
//         hash ^= (u64)(unsigned char)temp_event->qname[i];
//         hash *= prime;
//     }
    
//     return hash;
// }


struct hash_ctx {
    __u64 prime;
    struct dns_event *event;
    __u64               hash;
};

static int hash_dns_name(__u32 index, void *ctx_ptr) 
{
    struct hash_ctx *hctx = ctx_ptr;
    if (index >= MAX_QNAME_LEN)
    {
        return 1;
    }
    if (hctx->event->qname[index] == '\0') {
        return 1;
    }
    hctx->hash ^= (u64)(unsigned char)hctx->event->qname[index];
    hctx->hash *= hctx->prime;
    return 0;
}
