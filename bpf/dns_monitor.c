
// +build ignore

#include "include/vmlinux.h"
#include "include/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_QNAME_LEN 255
#define MAX_LABEL_COUNT 10
#define MAX_LABEL_LEN 63 
#define MAX_DNS_OFFSET 4096 


char LICENSE[] SEC("license") = "GPL";

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

struct dns_event {
    __u16 dns_type;
    __u16 qname_len;
    __u8 qname[MAX_QNAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB buffer for events (~4000 concurrent events capacity)
} events_ringbuf SEC(".maps");


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


static __always_inline int parse_dns(void **cursor, void *end) {
    struct dnshdr *dns = *cursor;
    if ((void*)(dns + 1) > end) {
        return DNS_UNKNOWN;
    }

    __u16 flags = bpf_ntohs(dns->flags);
    int is_response = (flags >> 15) & 1;
    if (!is_response) {
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


static __always_inline int safe_copy(__u8 *dst_pos, __u8 *dst_end, 
                                     __u8 *src, void *src_end, int len) {
    if ((void*)(src + len) > src_end)
    {
        return -1;
    }
    if (dst_pos + len > dst_end)
    {
        return -1;
    }
    
    if (bpf_probe_read_kernel(dst_pos, len, src) < 0) 
    {
        return -1;
    }

    return 0;
}

static __always_inline int read_label(struct dns_event *event, __u8 **cur, 
                                    void **cursor, void *end, 
                                    __u8 **crawler, __u8 *crawler_end) {
    __u8 len = **cur;
    if (len == 0 || len > MAX_LABEL_LEN) {
        return LABEL_ERR;
    }
    ++(*cur);
    ++(event->qname_len);
    **crawler = '.';
    ++(*crawler);

    if (*crawler + len > crawler_end) { 
        return LABEL_ERR;
    }
    if ((void*)(*cur + len) > end) {
        return LABEL_ERR;
    }

    if (safe_copy(*crawler, crawler_end, *cur, end, len) < 0) {
        return LABEL_ERR;
    }

    *cur += len;
    
    //*crawler += len;
    return LABEL_OK;
}

// RFC1035 
static __always_inline void parse_domain(void *start, void **cursor, void *end, int dns_type) {
    // if (MAX_QNAME_LEN > sizeof(struct dns_event)) {
    //     return;
    // }
    struct dns_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct dns_event), 0);
    if (!event) {
        return;
    }
    event->dns_type = dns_type;
    event->qname_len = 0;

    __u8 *crawler = event->qname;
    __u8 *crawler_end = event->qname + MAX_QNAME_LEN;

    int label_status = LABEL_ERR;

    for (int i = 0; i < MAX_LABEL_COUNT; i++) {
        __u8 *cur = *cursor;
        if ((void*)(cur + 1) > end) {
            label_status = LABEL_ERR;
            break;
        }
        if (*cur == 0) {
            *cursor = cur + 1;
            label_status = LABEL_DONE;
            break;
        }
        if (crawler + 1 == crawler_end) {
            label_status = LABEL_ERR;
            break;
        }
        if (*cur >> 6 == 0x03) {
            if ((void*)(cur + 2) > end) {
                label_status = LABEL_ERR;
                break;
            }
            *cursor = (void*)(cur + 2);
            __u16 raw_cur;
            __builtin_memcpy(&raw_cur, cur, 2);
            __u16 host_val = bpf_ntohs(raw_cur);
            __u16 offset = host_val & 0x3FFF; // (0b0011_1111_1111_1111)
            asm volatile("" : "+r"(offset)); // Force verifier to avoid any optimizations with offset
            if (offset > MAX_DNS_OFFSET) {
                label_status = LABEL_ERR;
                break;
            }
            __u8 *buff_start = start;
            if ((void*)(buff_start + offset) > end) {
                label_status = LABEL_ERR;
                break;
            }
            cur = buff_start + offset;
            if ((void*)(cur + 1) > end) {
                label_status = LABEL_ERR;
                break;
            }
            label_status = read_label(event, &cur, cursor, end, &crawler, crawler_end);
            break;
        }
        label_status = read_label(event, &cur, cursor, end, &crawler, crawler_end);
        if (label_status == LABEL_ERR) {
            break;
        }
        *cursor = (void*)cur;
    }

    if (label_status == LABEL_OK || label_status == LABEL_DONE) {
        bpf_ringbuf_submit(event, 0);
    } 
    else {
        bpf_ringbuf_discard(event, 0); 
    }

    return;
}


// static __always_inline int safe_copy(struct dns_event *event, 
//                                      __u32 dst_idx, __u32 dst_max,
//                                      __u8 *src, void *src_end, __u32 len) {

//     if ((void*)(src + len) > src_end)
//     {
//         return -1;
//     }
   
//     if (dst_idx + len > dst_max)
//     {
//         return -1;
//     }
//     __u32 max_len = dst_max - dst_idx;
//     if (len > max_len)
//         len = max_len;
    
//     __u8 *dst = event->qname + dst_idx;
//     if (bpf_probe_read_kernel(dst, len, src) < 0)
//     {
//         return -1;
//     }
        
    
//     return 0;
// }

// struct read_label_response {
//     int status;
//     __u8 *new_cursor;
//     __u8 *new_crawler;
// };

// static __always_inline int read_label(struct dns_event *event, __u8 **cur, 
//                                     void **cursor, void *end) {
//     __u8 len = **cur;
//     if (len == 0 || len > MAX_LABEL_LEN) {
//         return LABEL_ERR;
//     }
//     ++(*cur);
//     __u32 qname_len = event->qname_len;
//     ++qname_len;

//     __u32 idx = qname_len - 1;

//     if (idx >= MAX_QNAME_LEN) { 
//         return LABEL_ERR;
//     }
//     event->qname[idx] = '.';
//     ++idx;

//     if ((void*)(*cur + len) > end) {
//         return LABEL_ERR;
//     }

//     if (safe_copy(event, idx, MAX_QNAME_LEN, *cur, end, len) < 0) {
//         return LABEL_ERR;
//     }

//     *cur += len;
//     event->qname_len += len;
//     return LABEL_OK;
// }

// // RFC1035 
// static __always_inline void parse_domain(void *start, void **cursor, void *end, int dns_type) {
//     struct dns_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct dns_event), 0);
//     if (!event) {
//         return;
//     }
//     event->dns_type = dns_type;
//     event->qname_len = 0;

//     // __u32 cr_idx =  event->qname_len;

//     int label_status = LABEL_ERR;

//     for (int i = 0; i < MAX_LABEL_COUNT; i++) {
//         __u8 *cur = *cursor;
//         if ((void*)(cur + 1) > end) {
//             label_status = LABEL_ERR;
//             break;
//         }
//         if (*cur == 0) {
//             *cursor = cur + 1;
//             label_status = LABEL_DONE;
//             break;
//         }
//         if (event->qname_len + 1 > MAX_QNAME_LEN) {
//             label_status = LABEL_ERR;
//             break;
//         }
//         if (*cur >> 6 == 0x03) {
//             if ((void*)(cur + 2) > end) {
//                 label_status = LABEL_ERR;
//                 break;
//             }
//             *cursor = (void*)(cur + 2);
//             __u16 raw_cur;
//             __builtin_memcpy(&raw_cur, cur, 2);
//             __u16 host_val = bpf_ntohs(raw_cur);
//             __u16 offset = host_val & 0x3FFF; // (0b0011_1111_1111_1111)
//             asm volatile("" : "+r"(offset)); // Force verifier to avoid any optimizations with offset
//             if (offset > MAX_DNS_OFFSET) {
//                 label_status = LABEL_ERR;
//                 break;
//             }
//             __u8 *buff_start = start;
//             if ((void*)(buff_start + offset) > end) {
//                 label_status = LABEL_ERR;
//                 break;
//             }
//             cur = buff_start + offset;
//             if ((void*)(cur + 1) > end) {
//                 label_status = LABEL_ERR;
//                 break;
//             }
//             label_status = read_label(event, &cur, cursor, end);
//             break;
//         }
//         label_status = read_label(event, &cur, cursor, end);
//         if (label_status == LABEL_ERR) {
//             break;
//         }
//         *cursor = (void*)cur;
//     }

//     if (label_status == LABEL_OK || label_status == LABEL_DONE) {
//         bpf_ringbuf_submit(event, 0);
//     } 
//     else {
//         bpf_ringbuf_discard(event, 0); 
//     }

//     return;
// }


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
    
    if (cursor > frame_end) {
        return XDP_PASS;
    }
    void *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end);
    if (dns_type == DNS_UNKNOWN) {
        return XDP_PASS;
    }
    
    if (dns_type == DNS_QUERY || dns_type == DNS_RESPONSE_NXDOMAIN) {
        parse_domain(dns_start, &cursor, frame_end, dns_type);
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