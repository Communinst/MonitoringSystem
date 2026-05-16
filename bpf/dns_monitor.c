
// +build ignore
#include "./linux/vmlinux.h"
#include "./linux/if_ether.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "./include/dns_parse.h"
#include "./include/dns_parse_helper.h"

#include "./include/maps.h"
#include "./include/shared_maps.h"


char LICENSE[] SEC("license") = "GPL";

enum metric_index {
    dns_packet_type,
    METRIC_PASSED = 9,
    METRIC_ANOMALY_SIZE = 10,
    METRIC_POD_RESPOND = 11,
    METRIC_QUERY_TO_POD = 12,
    METRIC_UNREGISTERED_RESPONSE = 13,
    METRIC_PASSED_XDP_DNS = 14,
    METRIC_PASSED_XDP_QUERY = 15,
};

static __always_inline void increment_metric(void *map, __u32 index) {
    __u64 *value = bpf_map_lookup_elem(map, &index);
    if (value) {
        *value += 1;
    }
}

SEC("tc/ingress")
int tc_dns_ingress(struct __sk_buff *ctx) {
    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    int l4_proto = 0;
    struct hash_key h_key;
    __builtin_memset(&h_key, 0, sizeof(h_key));
    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            h_key.ip_v = 4;
            l4_proto = parse_ip_v4(&cursor, frame_end, &h_key.ip.ipv4);
        } 
        else 
        {
            h_key.ip_v = 6;
            l4_proto = parse_ip_v6(&cursor, frame_end, h_key.ip.ipv6, 16);
        }
    } 
    else 
    {
        return TC_ACT_OK;
    }

    // Handling subsequent fragments in XDP is extremely difficult, 
    // so pass them. Anyway they can't contain DNS header, so we won't lose 
    // any important information for XDP monitoring.
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
    // Dissect only DNS packets, pass the rest
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

    if (is_dns != DNS_YES) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }

    __u8 *dns_start = cursor;
    
    int dns_type = parse_dns(&cursor, frame_end, &h_key.TXID);
    if (dns_type == DNS_UNKNOWN) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    increment_metric(&tc_metrics_map, METRIC_PASSED);
    if (dns_type < DNS_QUERY)
    {
        increment_metric(&tc_metrics_map, METRIC_POD_RESPOND - 1); 
    }
    else 
    {
        increment_metric(&tc_metrics_map, DNS_QUERY - 1); 
    }

    __u32 key = 0;
    struct dns_event_xdp *temp_event = bpf_map_lookup_elem(&tc_ingress_scratchpad_map, &key);
    if (!temp_event) 
    {
        return TC_ACT_OK;
    }
    int status = parse_domain_filtered(cursor, frame_end, &temp_event->event);
    if (status > 0) // Was the compression met?
    {
        status = (status == 1) 
        ? parse_domain_compression(cursor, frame_end, dns_start, &temp_event->event)
        : status;
        cursor = (__u8 *)(cursor) + 2; // Move packet ptr for pointer size
    }
    if (status < 0) // Error occured?
    {
        return TC_ACT_OK;
    }
    cursor = (__u8 *)(cursor) + temp_event->event.qname_len;
    __u16 qname_len = temp_event->event.qname_len + temp_event->event.compression_len & 0xFF; 
    // there's qname_len as a cursor shift value compession_len adds up to overall qname length 
    if (qname_len == 0) 
    {
        return TC_ACT_OK;
    }
    temp_event->status = dns_type;
    temp_event->event.qname[qname_len - 1] = 0;

    struct hash_ctx hctx = 
    {
        .prime = 0x100000001b3ULL,
        .event = &temp_event->event,
        .hash = 0xcbf29ce484222325ULL,
    };
    bpf_loop(qname_len, hash_dns_name, &hctx, 0);
    h_key.hash = hctx.hash;

    __u64 timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&dns_hash_map, &h_key.hash, &timestamp, BPF_ANY);

    bpf_printk("TC/ingress: DNS event: qname=%s, type=%d", temp_event->event.qname, dns_type);

    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_dns_egress(struct __sk_buff *ctx) {
    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    int l4_proto = 0;
    struct hash_key h_key;
    __builtin_memset(&h_key, 0, sizeof(h_key));
    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            h_key.ip_v = 4;
            l4_proto = parse_ip_v4(&cursor, frame_end, &h_key.ip.ipv4);
        } 
        else 
        {
            h_key.ip_v = 6;
            l4_proto = parse_ip_v6(&cursor, frame_end, h_key.ip.ipv6, 16);
        }
    } 
    else 
    {
        return TC_ACT_OK;
    }

    // Handling subsequent fragments in XDP is extremely difficult, 
    // so pass them. Anyway they can't contain DNS header, so we won't lose 
    // any important information for XDP monitoring.
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
    // Dissect only DNS packets, pass the rest
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

    if (is_dns != DNS_YES) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }

    __u8 *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end, &h_key.TXID);
    if (dns_type == DNS_UNKNOWN) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    increment_metric(&tc_metrics_map, METRIC_PASSED);
    if (dns_type != DNS_QUERY) 
    {
        increment_metric(&tc_metrics_map, METRIC_POD_RESPOND); 
    }

    __u32 key = 0; 
    struct dns_event_xdp *temp_event = bpf_ringbuf_reserve(&dns_event_ringbuf, sizeof(struct dns_event_xdp), 0);
    if (!temp_event) 
    {
        return TC_ACT_OK;
    }
    int status = parse_domain_filtered(cursor, frame_end, &temp_event->event);
    if (status > 0) // Was the compression met?
    {
        status = (status == 1) 
        ? parse_domain_compression(cursor, frame_end, dns_start, &temp_event->event)
        : status;
        cursor = (__u8 *)(cursor) + 2; // Move packet ptr for pointer size
    }
    if (status < 0) // Error occured?
    {   
        bpf_ringbuf_discard(temp_event, 0);
        return TC_ACT_OK;
    }
    cursor = (__u8 *)(cursor) + temp_event->event.qname_len;
    __u16 qname_len = temp_event->event.qname_len + temp_event->event.compression_len & 0xFF; 
    // there's qname_len as a cursor shift value compession_len adds up to overall qname length 
    if (qname_len == 0) 
    {
        bpf_ringbuf_discard(temp_event, 0);
        return TC_ACT_OK;
    }
    temp_event->status = dns_type;
    temp_event->event.qname[qname_len - 1] = 0;

    struct hash_ctx hctx = 
    {
        .prime = 0x100000001b3ULL,
        .event = &temp_event->event,
        .hash = 0xcbf29ce484222325ULL,
    };
    bpf_loop(qname_len, hash_dns_name, &hctx, 0);
    h_key.hash = hctx.hash;
    __u64 *timestamp = bpf_map_lookup_elem(&dns_hash_map, &h_key);
    if (!timestamp) 
    {
        bpf_ringbuf_discard(temp_event, 0);
        increment_metric(&tc_metrics_map, METRIC_UNREGISTERED_RESPONSE); 
    }
    else 
    {
        bpf_map_delete_elem(&dns_hash_map, &key);
        temp_event->latency_ns = bpf_ktime_get_ns() - *timestamp;
        bpf_ringbuf_submit(temp_event, 0);
    }

    bpf_printk("DNS event: qname=%s, type=%d", temp_event->event.qname, dns_type);

    return TC_ACT_OK;
}

SEC("xdp")
int xdp_watch(struct xdp_md *ctx) 
{ 
    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) 
    {
        return XDP_PASS;
    }

    int l4_proto = 0;
    struct hash_key h_key = {};
    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            h_key.ip_v = 4;
            l4_proto = parse_ip_v4(&cursor, frame_end, &h_key.ip.ipv4);
        } 
        else 
        {
            h_key.ip_v = 6;
            l4_proto = parse_ip_v6(&cursor, frame_end, h_key.ip.ipv6, 16);
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

    if (l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_TCP) 
    {
        return XDP_PASS;
    }
    if (l4_proto == IPPROTO_UDP) 
    {   
        // is_dns = xdp_parse_vxlan_from_udp(&cursor, frame_end, &h_key);
        // if (is_dns != DNS_YES) {
        //     return XDP_PASS;
        // }
        is_dns = parse_udp_for_dns(&cursor, frame_end, &payload_len); // VXLAN expection included.
    } 
    else 
    {
        is_dns = parse_tcp_for_dns(&cursor, frame_end, &payload_len);
    }

    if (is_dns != DNS_YES) 
    {
        return XDP_PASS;
    }
    if (cursor >= frame_end) 
    {
        return XDP_PASS;
    }

    // __u8 *dns_start = cursor;
    int dns_type = parse_dns(&cursor, frame_end, &h_key.TXID);
    if (dns_type == DNS_UNKNOWN) 
    {
        return XDP_PASS;
    }
    if (cursor >= frame_end) 
    {
        return XDP_PASS;
    }
    increment_metric(&xdp_metrics_map, METRIC_PASSED_XDP_DNS - 1);
    if (dns_type == DNS_QUERY) 
    {
        increment_metric(&xdp_metrics_map, METRIC_PASSED_XDP_QUERY - 1); 
    }
    __u32 key = 0;
    __u32 *max_size = bpf_map_lookup_elem(&config_map, &key);
    if (max_size && payload_len > *max_size) 
    {
        increment_metric(&xdp_metrics_map, METRIC_ANOMALY_SIZE); 
    }

    bpf_printk("XDP: DNS event: type=%d", dns_type);

    return XDP_PASS;
}