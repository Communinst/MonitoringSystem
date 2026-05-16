#pragma once
#include "../linux/vmlinux.h"
#include "../linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "./dns_parse.h"




#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8 /* For hw path, this means "trap to cpu"
				   * and don't further process the frame
				   * in hardware. For sw path, this is
				   * equivalent of TC_ACT_STOLEN - drop
				   * the skb and act like everything
				   * is alright.
				   */
#define TC_ACT_VALUE_MAX	TC_ACT_TRAP

/* There is a special kind of actions called "extended actions",
 * which need a value parameter. These have a local opcode located in
 * the highest nibble, starting from 1. The rest of the bits
 * are used to carry the value. These two parts together make
 * a combined opcode.
 */
#define __TC_ACT_EXT_SHIFT 28
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_EXT_OPCODE(combined) ((combined) & (~TC_ACT_EXT_VAL_MASK))
#define TC_ACT_EXT_CMP(combined, opcode) (TC_ACT_EXT_OPCODE(combined) == opcode)

#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#define TC_ACT_EXT_OPCODE_MAX	TC_ACT_GOTO_CHAIN

/* These macros are put here for binary compatibility with userspace apps that
 * make use of them. For kernel code and new userspace apps, use the TCA_ID_*
 * versions.
 */
#define TCA_ACT_GACT 5
#define TCA_ACT_IPT 6 /* obsoleted, can be reused */
#define TCA_ACT_PEDIT 7
#define TCA_ACT_MIRRED 8
#define TCA_ACT_NAT 9
#define TCA_ACT_XT 10
#define TCA_ACT_SKBEDIT 11
#define TCA_ACT_VLAN 12
#define TCA_ACT_BPF 13
#define TCA_ACT_CONNMARK 14
#define TCA_ACT_SKBMOD 15
#define TCA_ACT_CSUM 16
#define TCA_ACT_TUNNEL_KEY 17
#define TCA_ACT_SIMP 22
#define TCA_ACT_IFE 25
#define TCA_ACT_SAMPLE 26


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
