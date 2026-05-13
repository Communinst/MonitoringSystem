
// +build ignore

#include "./linux/vmlinux.h"
#include "./linux/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "./include/dns_parse.h"
#include "./include/maps.h"
#include <linux/pkt_cls.h>


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

SEC("tc")
int tc_watch(struct __sk_buff *ctx) {
    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) {
        return TC_ACT_OK;
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
        return TC_ACT_OK;
    }

    if (l4_proto < FRAG_HEAD) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    
    // Only UDP and TCP accepted.
    __u16 payload_len = 0;
    int is_dns = 0;
    if (l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_TCP) 
    {
        return TC_ACT_OK;
    }

    if (l4_proto == IPPROTO_UDP) 
    {
        is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len);
    } 
    else 
    {
        is_dns = parse_tcp_for_dns(&cursor, frame_end, &payload_len);
    }
    
    if (is_dns != DNS_YES) {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) {
        return TC_ACT_OK;
    }

    __u8 *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end);
    if (dns_type == DNS_UNKNOWN) {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) {
        return TC_ACT_OK;
    }

    if (dns_type == DNS_RESPONSE_NXDOMAIN) 
    {
        increment_metric(2); 
    }
    __u32 key = 0;

    __u8 *buff = (__u8 *)(cursor); // take a buff of cursor to 
    // make clear the whole domain name shift procedure
    struct dns_event *temp_event = bpf_map_lookup_elem(&scratchpad_map, &key);
    if (!temp_event) 
    {
        return TC_ACT_OK;
    }
    int status = parse_domain_filtered(cursor, frame_end, temp_event);
    if (status > 0) {
        status = (status == 1) 
        ? parse_domain_compression(cursor, frame_end, dns_start, temp_event)
        : status;
        buff += 2;
    }
    if (status < 0) 
    {
        return TC_ACT_OK;
    }
    __u8 qname_len = temp_event->qname_len & 0xFF; 
    if (qname_len == 0 || qname_len > MAX_QNAME_LEN)
    {
        return TC_ACT_OK;
    }
    temp_event->dns_type = dns_type;
    temp_event->qname[qname_len - 1] = 0;

    buff += temp_event->qname_len;
    if ((void*)(buff) >= frame_end) 
    {
        return TC_ACT_OK;
    }
    cursor = (void*)(buff);
    

    return TC_ACT_OK;
 }