#pragma once

#include "../linux/vmlinux.h"
#include "../linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>
#include "./maps.h"

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
    __u16 dns_type;
    __u16 qname_len;
    __u8 qname[MAX_QNAME_LEN];
};

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

    // 802.1AD 
    if (eth_type == ETH_P_8021AD) {
        struct vlan_hdr *ad = *cursor;
        
        if ((void *)(ad + 1) > end) {
            return -1; // frame corrupted
        }
        eth_type = bpf_ntohs(ad->h_vlan_encapsulated_proto);

        *cursor = (void *)(ad + 1);
    }  

    // 802.1Q 
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *ad = *cursor;
        
        if ((void *)(ad + 1) > end) {
            return -1; // frame corrupted
        }
        eth_type = bpf_ntohs(ad->h_vlan_encapsulated_proto);
        
        *cursor = (void *)(ad + 1);
    }

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

    for (int i = 0; i < 4; i++) {
        if (nexthdr == 44) { // NEXTHDR_FRAGMENT
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
        } else if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) { 
            // NEXTHDR_HOP (0), NEXTHDR_ROUTING (43), NEXTHDR_DEST (60)
            struct { __u8 next; __u8 len; } *ext = buf_cursor;
            if ((void*)(ext + 1) > end) {
                return CORRUPTED;
            }
            nexthdr = ext->next;
            buf_cursor += (ext->len + 1) * 8;
            if (buf_cursor > end) {
                return CORRUPTED;
            }
        } else {
            break;
        }
    }

    *cursor = buf_cursor;
    return nexthdr;
}


static __always_inline int parse_ip(void **cursor, void const *end, int ip_type) {
    switch (ip_type) {
        case ETH_P_IP:
            return parse_ip_v4(cursor, end);
        case ETH_P_IPV6:
            return parse_ip_v6(cursor, end);
        default:
            return -1;
    }
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

    if (src_port == 53 || dest_port == 53) {
        return DNS_YES;
    }

    return DNS_NO;
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

    if (src_port == 53 || dest_port == 53) {
        // TCP DNS messages have a 2-byte length prefix
        __be16 *len_ptr = *cursor;
        if ((void*)(len_ptr + 1) > end) {
            return DNS_UNKNOWN; 
        }
        *payload_len = bpf_ntohs(*len_ptr);
        *cursor = (void *)(len_ptr + 1);

        return DNS_YES;
    }

    return DNS_NO;
}

static __always_inline int parse_for_dns(void **cursor, void *end, int l4_proto, __u16 *payload_len) {
    switch (l4_proto) {
        case IPPROTO_UDP:
            return parse_udp_for_dns(cursor, end, payload_len);
        case IPPROTO_TCP:
            return parse_tcp_for_dns(cursor, end, payload_len);
        default:
            return DNS_NO;
    }
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

    if (rcode == 3) {
        return DNS_RESPONSE_NXDOMAIN;
    } else if (rcode == 0) {
        return DNS_RESPONSE_OK;
    }
    
    return DNS_RESPONSE_OTHER;
}


// static __always_inline int parse_domain(void *start, void **cursor, void *end, int dns_type) 
// {
//     struct dns_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct dns_event), 0);
//     if (!event) 
//     {
//         return -1;
//     }
//     event->dns_type = dns_type;
//     event->qname_len = 0;
//     __u8 *cur = *cursor;

//     #pragma unroll
//     for (int i = 0; i < MAX_QNAME_LEN; i++) 
//     {
//         if ((void*)(cur + 1) > end) 
//         {
//             bpf_ringbuf_discard(event, 0); 
//             return -1;
//         }

//         event->qname[event->qname_len] = *cur;
//         ++event->qname_len;
//         if (*cur == 0) {
//             break;
//         }
//         ++cur;
//     }

//     bpf_ringbuf_submit(event, 0);
//     *cursor = (void *)(cur + 1);
//     return 0;
// }


static __always_inline int parse_domain(void *start, void **cursor, void *end, int dns_type) 
{
    struct dns_event *temp_event = bpf_map_lookup_elem(&scratchpad_map, &(const __u32){0});
    temp_event->dns_type = dns_type;
    temp_event->qname_len = 0;
    __builtin_memset(temp_event->qname, 0, 255);

    __u8* dns_payload = *cursor;

    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN; i++) 
    {
        if ((void*)(dns_payload + i) >= end) 
        {
            return -1;
        }
        if (*dns_payload == 0) {
            temp_event->qname_len = i + 1;
            break;
        }
        temp_event->qname[i] = *(dns_payload + i);
    }
    
    return 0;
}
