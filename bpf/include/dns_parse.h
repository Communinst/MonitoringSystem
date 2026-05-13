#pragma once

#include "../linux/vmlinux.h"
#include "../linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>
#include "./maps.h"

#define MAX_QNAME_LEN_CLOSET_TWO 256
#define MAX_QNAME_LEN 255
#define MAX_LABEL_COUNT 127
#define MAX_LABEL_LEN 63 
#define MAX_DNS_OFFSET 4096 
#define DNS_PORT 53


enum packet_status {
    PACKET_CORRUPTED = -1,
    PACKET_OK = 0,
};

enum is_DNS 
{
    CORRUPTED = -1,
    DNS_NO = 0,
    DNS_YES = 1,
};

enum dns_packet_type
{
    DNS_UNKNOWN = -1,
    DNS_QUERY = 0,
    DNS_RESPONSE_OK = 1,
    DNS_RESPONSE_NXDOMAIN = 2,
    DNS_RESPONSE_OTHER = 3,
};

enum ip_frag {
    FRAG_SUBSEQUENT = -2, 
    FRAG_HEAD = 0,
};

enum label_status {
    LABEL_ERR = -1,
    LABEL_OK = 0,
    LABEL_DONE = 1,
};

struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

struct dns_event {
    __u16 qname_len;
    __u8 qname[MAX_QNAME_LEN_CLOSET_TWO]; //256 
    __u8 compression_len;
};

struct dns_event_xdp {
    struct dns_event event; 
    __u64 latency_ns;
    __u8 status;
}; // 264 + 8 + 1 + 7(padding) OR 260 + 8 + 1 + 3

// static __always_inline void increment_metric(__u32 index) {
//     __u64 *value = bpf_map_lookup_elem(&metrics_map, &index);
//     if (value) {
//         *value += 1;
//     }
// }

static __always_inline int parse_eth(void **cursor, void const *end) {
    struct ethhdr *eth = *cursor; // Assuming Eth frame accepted

    if ((void *)(eth + 1) > end) {
        return -1; // frame corrupted
    }

    // Parse type
    long eth_type = bpf_ntohs(eth->h_proto);
    *cursor = (void *)(eth + 1); 

    // IPv4 or IPv6
    return eth_type;
}


static __always_inline int parse_ip_v4 (void **cursor, void const *end) {
    struct iphdr *ip = *cursor;

    if ((void*)(ip + 1) > end) {
        return CORRUPTED;
    }  
    if (ip->version != 4) {
        return CORRUPTED;
    } 
    __u32 hdr_len = ip->ihl * 4; // Since IP packet's ihl field expressed in 32-bit words
    if (hdr_len < 20) {
        return CORRUPTED;
    }
    
    // Check if this is a fragment (and NOT the first fragment)
    // frag_off & IP_OFFSET (0x1FFF)
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if ((frag_off & 0x1FFF) != 0) {
        return FRAG_SUBSEQUENT; // Subsequent fragment
    }

    void *buf_cursor = (__u8 *)*cursor + hdr_len;
    if (buf_cursor > end) {
        return CORRUPTED;
    }
    *cursor = buf_cursor;

    return ip->protocol;
}

static __always_inline int parse_ip_v6(void **cursor, void const *end) {
    struct ipv6hdr *ipv6 = *cursor;

    if ((void*)(ipv6 + 1) > end) {
        return CORRUPTED;
    }  
    if (ipv6->version != 6) {
        return CORRUPTED;
    } 
    
    int nexthdr = ipv6->nexthdr;
    void *buf_cursor = (void *)(ipv6 + 1);

    #pragma unroll
    for (int i = 0; i < 4; ++i) 
    {
        if (nexthdr != 44 && nexthdr != 0 && nexthdr != 43 && nexthdr != 60) 
        {
            break;
        }
        if (nexthdr == 44) 
        { // NEXTHDR_FRAGMENT
            struct frag_hdr *frag = buf_cursor;
            if ((void*)(frag + 1) > end) {
                return CORRUPTED;
            }
            
            __u16 frag_off = bpf_ntohs(frag->frag_off);
            // Fragment offset is in bits 3-15 (mask 0xFFF8)
            if ((frag_off & 0xFFF8) != 0) {
                return FRAG_SUBSEQUENT; // Subsequent fragment
            }
            
            nexthdr = frag->nexthdr;
            buf_cursor = (void *)(frag + 1);
        } 
        else 
        { 
            struct { __u8 next; __u8 len; } *ext = buf_cursor;
            if ((void*)(ext + 1) > end) {
                return CORRUPTED;
            }
            nexthdr = ext->next;
            buf_cursor += (ext->len + 1) * 8;
            if (buf_cursor > end) {
                return CORRUPTED;
            }
        } 
    }

    *cursor = buf_cursor;
    return nexthdr;
}


static __always_inline int parse_udp_for_dns(void **cursor, void *end, __u16 *udp_payload_len) {
    struct udphdr *udp = *cursor;

    if ((void*)(udp + 1) > end) {
        return DNS_NO;
    }

    int src_port = bpf_ntohs(udp->source);
    int dest_port = bpf_ntohs(udp->dest);
    
    __u16 total_udp_len = bpf_ntohs(udp->len);
    if (total_udp_len >= sizeof(struct udphdr)) {
        *udp_payload_len = total_udp_len - sizeof(struct udphdr);
    } else {
        *udp_payload_len = 0;
    }

    *cursor = (void *)(udp + 1);

    if (src_port != 53 && dest_port != 53) {
        return DNS_NO;
    }

    return DNS_YES;
}



static __always_inline int parse_tcp_for_dns(void **cursor, void *end, __u16 *payload_len) {
    struct tcphdr *tcp = *cursor;

    if ((void*)(tcp + 1) > end) {
        return DNS_NO;
    }

    int src_port = bpf_ntohs(tcp->source);
    int dest_port = bpf_ntohs(tcp->dest);
    
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) {
        return DNS_NO;
    }

    void *buf_cursor = *cursor + tcp_hdr_len;
    if (buf_cursor > end) {
        return DNS_NO;
    }

    *cursor = buf_cursor;

    if (src_port != 53 && dest_port != 53) {
        return DNS_NO;
    }
    __be16 *len_ptr = *cursor;
    if ((void*)(len_ptr + 1) > end) {
        return DNS_UNKNOWN; 
    }
    *payload_len = bpf_ntohs(*len_ptr);
    *cursor = (void *)(len_ptr + 1);
    return DNS_YES;
    
}

static __always_inline int parse_dns(void **cursor, void *end) {
    struct dnshdr *dns = *cursor;
    if ((void*)(dns + 1) > end) {
        return DNS_UNKNOWN;
    }

    __u16 flags = bpf_ntohs(dns->flags);
    int is_response = (flags >> 15) & 1;
    if (!is_response) {
        *cursor = (void*)(dns + 1); 
        return DNS_QUERY;
    }

    int rcode = flags & 0x0F;
    *cursor = (void*)(dns + 1);

    if (rcode == 3) 
    {
        return DNS_RESPONSE_NXDOMAIN;
    }
    if (rcode == 0) 
    {
        return DNS_RESPONSE_OK;
    }
    return DNS_RESPONSE_OTHER;
}


struct domain_compression_ctx {
    void             *end;
    __u8             *payload;
    struct dns_event *event;
    int               result;
    __u8              label_within;
};

static int domain_compression_cb(__u32 index, void *ctx_ptr)
{
    struct domain_compression_ctx *lctx = ctx_ptr;

    __u8 *current = lctx->payload; 
    if ((void *)(current + 1) > lctx->end)
    {
        lctx->result = -1;
        return 1;
    }

    if (*current == 0)
    {
        lctx->event->compression_len = index;
        lctx->result = 0;
        return 1; // stop
    }
    if (lctx->label_within == 0)
    {
        if (*current > MAX_LABEL_LEN || *current == 0)
        {
            lctx->result = -1;
            return 1;
        }
        lctx->label_within = *current;
        *current = '.';
    }
    else
    {
        lctx->label_within--;
    }

    // Теперь верификатор видит: qname_idx < MAX_QNAME_LEN — запись безопасна
    if (index + lctx->event->qname_len >= MAX_QNAME_LEN) 
    {
        lctx->result = -1;
        return 1;
    }
    lctx->event->qname[lctx->event->qname_len + index] = *current;
    ++lctx->payload;

    return 0; // continue
}

static __always_inline int parse_domain_compression(
    void *cursor, 
    void *end, 
    void *start, 
    struct dns_event *temp_event)
{
    __u8 *dns_payload = (__u8 *)(cursor) + temp_event->qname_len;

    if ((void *)(dns_payload + 2) > end)
    {
        return -1;
    }
        
    __u16 offset = (((__u16)*dns_payload) << 8 | *(dns_payload + 1)) & 0x3FFF;
    if (offset < sizeof(struct dnshdr) || offset > MAX_DNS_OFFSET)
    {
        return -1;
    }

    dns_payload = (__u8 *)start + offset;
    if ((void *)(dns_payload + 1) > end)
    {
        return -1;
    }
        
    if (temp_event->qname_len >= MAX_QNAME_LEN)
    {
        return -1;
    }

    struct domain_compression_ctx lctx = {
        .end         = end,
        .payload     = dns_payload,
        .event       = temp_event,
        .result      = -1,
        .label_within = 0,
    };

    bpf_loop(MAX_QNAME_LEN - temp_event->qname_len, domain_compression_cb, &lctx, 0);

    return lctx.result;
}

static __always_inline int parse_domain_filtered(void *cursor, void *end, struct dns_event *temp_event) 
{
    temp_event->qname_len = 0;
    temp_event->compression_len = 0;

    __u8* dns_payload = cursor;
    __u8 label_within = 0;
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN; ++i) 
    {
        if ((void*)(dns_payload + 1) > end) 
        {
            return -1;
        }
        __u8 current = *dns_payload;
        if (current == 0) 
        {   
            temp_event->qname_len = i + 1;
            break;
        }
        if (current >> 6 == 0x03) 
        {   
            temp_event->qname_len = i;
            return 1;
        }
        if (label_within == 0) 
        {
            label_within = current;
            if (label_within == 0 || label_within > MAX_LABEL_LEN) 
            {
                return -1;
            }
            if ((void*)(dns_payload + label_within + 1) > end) 
            {
                return -1;
            }
            current = '.';
        }
        else 
        {
            --label_within;
        }
        temp_event->qname[i] = current;
        ++dns_payload;
    }

    return 0;
}

