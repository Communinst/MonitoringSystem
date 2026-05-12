
// +build ignore

#include "./linux/vmlinux.h"
#include "./linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "./include/dns_parse.h"
#include "./include/maps.h"

char LICENSE[] SEC("license") = "GPL";



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


static __always_inline void increment_metric(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&metrics_map, &index);
    if (value) {
        *value += 1;
    }
}

SEC("xdp")
int xdp_watch(struct xdp_md *ctx) { // Supports VLANs and default eth frame
    // Ethernet-Packet-UDP-DnsRequest
    void *cursor = (void *)(long)ctx->data; // Cursor pattern allows to decrease amount of ctx mem approaches
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) {
        return XDP_PASS;
    }
    int l4_proto = 0;
    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            l4_proto = parse_ip_v4(&cursor, frame_end);
        } 
        else 
        {
            l4_proto = parse_ip_v6(&cursor, frame_end);
        }
    } 
    else 
    {
        return XDP_PASS;
    }

    // Handling subsequent fragments in XDP is extremely difficult, 
    // so pass them. Anyway they can't contain DNS header, so we won't lose 
    // any important information for XDP monitoring.
    if (l4_proto < FRAG_HEAD) 
    {
        return XDP_PASS;
    }
    if (cursor >= frame_end) 
    {
        return XDP_PASS;
    }
    
    // Only UDP and TCP accepted.
    __u16 payload_len = 0;
    int is_dns = 0;
    // Dissect only DNS packets, pass the rest
    // if (l4_proto == IPPROTO_UDP || l4_proto == IPPROTO_TCP) 
    // {
    //     if (l4_proto == IPPROTO_UDP) 
    //     {
    //         is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len);
    //     } 
    //     else 
    //     {
    //         is_dns = parse_tcp_for_dns(&cursor, frame_end, &payload_len);
    //     }
    // } 
    // else 
    // {
    //     return XDP_PASS;
    // }
    if (l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_TCP) 
    {
        return XDP_PASS;
    }
    if (l4_proto == IPPROTO_UDP) 
    {
        is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len);
    } 
    else 
    {
        is_dns = parse_tcp_for_dns(&cursor, frame_end, &payload_len);
    }
    // if (l4_proto != IPPROTO_UDP) 
    // {
    //     return XDP_PASS;
    // } 
    // is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len);

    if (is_dns != DNS_YES) {
        return XDP_PASS;
    }
    if (cursor >= frame_end) {
        return XDP_PASS;
    }

    __u8 *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end);
    if (dns_type == DNS_UNKNOWN) {
        return XDP_PASS;
    }
    if (cursor >= frame_end) {
        return XDP_PASS;
    }

    if (dns_type == DNS_RESPONSE_NXDOMAIN) 
    {
        increment_metric(2); 
    }
    __u32 key = 0;
    __u32 *max_size = bpf_map_lookup_elem(&config_map, &key);
    if (max_size && payload_len > *max_size) {
        increment_metric(1); 
        return XDP_DROP;
    }
    increment_metric(0);
     

    struct dns_event *temp_event = bpf_map_lookup_elem(&scratchpad_map, &key);
    if (!temp_event) 
    {
        return XDP_PASS;
    }
    int status = parse_domain_filtered(cursor, frame_end, temp_event);
    if (status > 0) {
        status = (status == 1) 
        ? parse_domain_compression(cursor, frame_end, dns_start, temp_event)
        : status;
    }
    if (status < 0) 
    {
        return XDP_PASS;
    }
    

    
    __u8 qname_len = temp_event->qname_len & 0xFF; 
    if (qname_len == 0 || qname_len > MAX_QNAME_LEN)
    {
        return XDP_PASS;
    }
    temp_event->dns_type = dns_type;
    temp_event->qname[qname_len - 1] = 0;

    __u8 *buff = (__u8 *)(cursor) + temp_event->qname_len;
    if ((void*)(buff) >= frame_end) 
    {
        return XDP_PASS;
    }
    cursor = (void*)(buff);
    

    return XDP_PASS;
 }