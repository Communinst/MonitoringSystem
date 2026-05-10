
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

    // IPv4 or IPv6
    int l4_proto = parse_ip(&cursor, frame_end, ip_type);
    // Handling subsequent fragments in XDP is extremely difficult, 
    // so pass them. Anyway they can't contain DNS header, so we won't lose 
    // any important information for XDP monitoring.
    if (l4_proto < 0) {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) {
        return TC_ACT_OK;
    }

    // Only UDP and TCP accepted.
    __u16 payload_len = 0;
    int is_dns = parse_for_dns(cursor, frame_end, l4_proto, &payload_len);
    // Dissect only DNS packets, pass the rest
    if (is_dns != DNS_YES) {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) {
        return TC_ACT_OK;
    }

    void *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end);
    if (dns_type == DNS_UNKNOWN) {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) {
        return TC_ACT_OK;
    }
    
    if (dns_type == DNS_QUERY || dns_type == DNS_RESPONSE_NXDOMAIN) {
        parse_domain(dns_start, &cursor, frame_end, dns_type);
    }

    if (dns_type == DNS_QUERY) {
        increment_metric(0);
        return TC_ACT_OK;
    }
    else if (dns_type == DNS_RESPONSE_OK || dns_type == DNS_RESPONSE_NXDOMAIN || dns_type == DNS_RESPONSE_OTHER) {
        if (dns_type == DNS_RESPONSE_NXDOMAIN) {
            increment_metric(2);
        }
    }

    increment_metric(0);
    return TC_ACT_OK;
}