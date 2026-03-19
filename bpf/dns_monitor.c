
// +build ignore

#include "include/vmlinux.h"
#include "include/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum
{
    DNS_QUERY = 0,
    DNS_RESPONSE = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); // Индекс 0: пропущено, Индекс 1: дропнуто
    __type(key, __u32);
    __type(value, __u64); // Счетчик пакетов
} metrics_map SEC(".maps");

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
        return -1;
    }  
    if (ip->version != 4) {
        return -1;
    } 
    int hdr_len = ip->ihl * 4; // Since IP packet's ihl field expressed in 32-bit words
    if (hdr_len < 20) {
        return -1;
    }
    
    void *buf_cursor = *cursor + hdr_len;
    *cursor = buf_cursor;

    return ip->protocol;
}

static __always_inline int parse_udp_for_dns(void **cursor, void *end, __u16 *udp_payload_len) {
    struct udphdr *udp = *cursor;

    if ((void*)(udp + 1) > end) {
        return -1;
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

    if (src_port == 53) {
        return DNS_RESPONSE;
    } 
    else if (dest_port == 53){
        return DNS_QUERY;
    }

    return -1;
}

SEC("xdp")
int xdp_watch(struct xdp_md *ctx) { // Supports VLANs and default eth frame
    // Ethernet-Packet-UDP-DnsRequest
    void *cursor = (void *)(long)ctx->data; // Cursor pattern allows to decrease amount of ctx mem approaches
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    // IPv4
    if (ip_type != ETH_P_IP) {
        return XDP_PASS;
    }
    
    int udp_proto = parse_ip_v4(&cursor, frame_end);
    // Only UDP accepted
    if (udp_proto != IPPROTO_UDP) { 
        return XDP_PASS;
    }

    __u16 udp_payload_len = 0;
    int dns_type = parse_udp_for_dns(&cursor, frame_end, &udp_payload_len);

    // Pass everything different from DNS
    if (dns_type < 0) {
        return XDP_PASS;
    }
    if (dns_type == DNS_QUERY) {
        
        return XDP_PASS;
    }
    else if (dns_type == DNS_RESPONSE) {
        __u32 key = 0;
        __u32 *max_size = bpf_map_lookup_elem(&config_map, &key);
        
        // Amplification protection
        if (max_size && udp_payload_len > *max_size) {
            increment_metric(1); 
            return XDP_DROP;
        }
    }

    increment_metric(0);
    return XDP_PASS;
 }