
// +build ignore

#include "include/vmlinux.h"
#include "include/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3); // 0: passed, 1: dropped, 2: NXDOMAIN;
    __type(key, __u32);
    __type(value, __u64); // Счетчик пакетов
} metrics_map SEC(".maps");

struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
//     __uint(max_entries, )
// }

static __always_inline void increment_metric(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&metrics_map, &index);
    if (value) {
        *value += 1;
    }
}

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
    int hdr_len = ip->ihl * 4; // Since IP packet's ihl field expressed in 32-bit words
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
    
    int tcp_hdr_len = tcp->doff * 4;
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

static __always_inline int parse_dns(void **cursor, void *end) {
    struct dnshdr *dns = *cursor;
    if ((void*)(dns + 1) > end) {
        return DNS_UNKNOWN;
    }

    __u16 flags = bpf_ntohs(dns->flags);
    int is_response = (flags >> 15) & 1;
    int rcode = flags & 0x0F;

    *cursor = (void*)(dns + 1);

    if (!is_response) {
        return DNS_QUERY;
    }

    if (rcode == 3) {
        return DNS_RESPONSE_NXDOMAIN;
    } else if (rcode == 0) {
        return DNS_RESPONSE_OK;
    }
    
    return DNS_RESPONSE_OTHER;
}

SEC("xdp")
int xdp_watch(struct xdp_md *ctx) { // Supports VLANs and default eth frame
    // Ethernet-Packet-UDP-DnsRequest
    void *cursor = (void *)(long)ctx->data; // Cursor pattern allows to decrease amount of ctx mem approaches
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);

    // IPv4 or IPv6
    int l4_proto = -1;
    if (ip_type == ETH_P_IP) {
        l4_proto = parse_ip_v4(&cursor, frame_end);
    } 
    else if (ip_type == ETH_P_IPV6) {
        l4_proto = parse_ip_v6(&cursor, frame_end);
    } 
    else {
        return XDP_PASS;
    }
    // Handling subsequent fragments in XDP is extremely difficult, 
    // so pass them. Anyway they can't contain DNS header, so we won't lose 
    // any important information for XDP monitoring.
    if (l4_proto < FRAG_HEAD) {
        return XDP_PASS;
    }
    
    // Only UDP and TCP accepted.
    __u16 payload_len = 0;
    int is_dns = DNS_NO;
    
    if (l4_proto == IPPROTO_UDP) {
        is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len);
    } 
    else if (l4_proto == IPPROTO_TCP) {
        is_dns = parse_tcp_for_dns(&cursor, frame_end, &payload_len);
    } 
    else {
        return XDP_PASS;
    }

    // Dissect only DNS packets, pass the rest
    if (is_dns != DNS_YES) {
        return XDP_PASS;
    }

    int dns_type = parse_dns(&cursor, frame_end);
    if (dns_type == DNS_UNKNOWN) {
        return XDP_PASS;
    }
    
    if (dns_type == DNS_QUERY) {
        increment_metric(0);
        return XDP_PASS;
    }
    else if (dns_type == DNS_RESPONSE_OK || dns_type == DNS_RESPONSE_NXDOMAIN || dns_type == DNS_RESPONSE_OTHER) {
        __u32 key = 0;
        __u32 *max_size = bpf_map_lookup_elem(&config_map, &key);
        
        // Amplification protection
        if (max_size && payload_len > *max_size) {
            increment_metric(1); 
            return XDP_DROP;
        }
        
        if (dns_type == DNS_RESPONSE_NXDOMAIN) {
            increment_metric(2);
        }
    }

    increment_metric(0);
    return XDP_PASS;
 }