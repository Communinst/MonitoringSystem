
// +build ignore
#include "./linux/vmlinux.h"
#include "./linux/if_ether.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "./include/dns_parse.h"
#include "./include/dns_parse_helper.h"

#include "./include/maps.h"
#include "./include/shared_maps.h"

#define POD_AMOUNT_LIMIT 128


char LICENSE[] SEC("license") = "GPL";

enum tc_metric_index {
    METRIC_NOERROR = 0,
    METRIC_FORMERR = 1,
    METRIC_SERVFAIL = 2,
    METRIC_NXDOMAIN = 3,
    METRIC_NOTIMP = 4,
    METRIC_REFUSED = 5,
    METRIC_DNS_RESPONSE_OTHER = 6,
    METRIC_DNS_QUERY = 7,
    METRIC_PASSED = 8,
    METRIC_ANOMALY_SIZE = 9,
    METRIC_POD_RESPOND = 10,
    METRIC_QUERY_TO_POD = 11,
    METRIC_UNREGISTERED_TRAFFIC = 12,
    METRIC_MAX_INDEX = 13,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct veth_key);
    __type(value, __u64);
    __uint(max_entries, METRIC_MAX_INDEX * POD_AMOUNT_LIMIT);
} tc_metrics_map SEC(".maps");


enum xdp_metric_index {
    METRIC_PASSED_XDP_DNS = 0,
    METRIC_PASSED_ANOMALY_SIZE = 1,
    METRIC_PASSED_XDP_QUERY = 2,
    METRIC_PASSED_XDP_NXDOMAIN = 3,
    METRIC_PASSED_XDP_MAX_INDEX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_PASSED_XDP_MAX_INDEX); // 0: passed, 1: anomaly_size, 2: NXDOMAIN, 3: anomaly_unexpeceted_packet;
    __type(key, __u32);
    __type(value, __u64); // Счетчик пакетов
} xdp_metrics_map SEC(".maps");


static __always_inline void increment_metric(void *map, struct veth_key *v_key) {
    __u64 *value = bpf_map_lookup_elem(map, v_key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(map, v_key, &init, BPF_NOEXIST);
    }
}

SEC("tc/ingress")
int tc_dns_ingress(struct __sk_buff *ctx) {
    bpf_skb_pull_data(ctx, 0);

    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    // bpf_printk("TC ingress preparse: initiated");

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    int l4_proto = 0;
    struct hash_key h_key;
    __builtin_memset(&h_key, 0, sizeof(h_key));
    struct src_ip_add dst_ip;
    __builtin_memset(&dst_ip, 0, sizeof(dst_ip));

    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            h_key.src_ip.ip_v = 4;
            dst_ip.ip_v = 4;
            l4_proto = parse_ip_v4(&cursor, frame_end, &h_key.src_ip.ip.ipv4, &dst_ip.ip.ipv4);
        } 
        else 
        {
            h_key.src_ip.ip_v = 6;
            dst_ip.ip_v = 6;
            l4_proto = parse_ip_v6(&cursor, frame_end, h_key.src_ip.ip.ipv6, dst_ip.ip.ipv6, 16);
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
    // bpf_printk("TC ingress preparse: post-*-for_dns");
    if (is_dns != DNS_YES) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }

    __u8 *dns_start = cursor;
    
    bpf_printk("TC ingress preparse: dns_type");

    int dns_type = parse_dns(&cursor, frame_end, &h_key.TXID);
    if (dns_type == DNS_UNKNOWN) 
    {
        return TC_ACT_OK;
    }
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    } 
    bpf_printk("TC ingress: dns_type=%d", dns_type);
    struct dns_event_full *temp_event = bpf_ringbuf_reserve(&dns_event_ringbuf, sizeof(struct dns_event_full), 0);
    if (!temp_event) 
    {
        return TC_ACT_OK;
    }
    temp_event->dst_ip = dst_ip;
    struct veth_key v_key = {
        .metric_key = METRIC_PASSED,
        .src_ip = h_key.src_ip,
    };
    increment_metric(&tc_metrics_map, &v_key);
    if (dns_type < METRIC_DNS_QUERY)
    {
        v_key.metric_key = METRIC_POD_RESPOND;
        increment_metric(&tc_metrics_map, &v_key); 
    }
    else 
    {
        v_key.metric_key = METRIC_DNS_QUERY;
        increment_metric(&tc_metrics_map, &v_key); 
    }

    temp_event->src_ip = h_key.src_ip;
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
        goto discard;
    }

    cursor = (__u8 *)(cursor) + temp_event->event.qname_len;
    __u16 qname_len = (temp_event->event.qname_len + temp_event->event.compression_len) & 0xFF; 
    // there's qname_len as a cursor shift value compession_len adds up to overall qname length 
    if (qname_len == 0) 
    {
        goto discard;
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
    bpf_map_update_elem(&dns_hash_map, &h_key, &timestamp, BPF_ANY);


    temp_event->timestamp_ns = timestamp;
    temp_event->latency_ns = 0; // It's just a query, no latency yet
    // __u16 *qtype_ptr = (__u16 *)cursor;
    // if ((void *)(qtype_ptr + 1) > frame_end) {
    //     goto discard;
    // }
    // temp_event->qtype = bpf_ntohs(*qtype_ptr);

    bpf_ringbuf_submit(temp_event, 0);
    return TC_ACT_OK;

    discard:
        bpf_ringbuf_discard(temp_event, 0);
        return TC_ACT_OK;
}



SEC("tc/egress")
int tc_dns_egress(struct __sk_buff *ctx) {
    bpf_skb_pull_data(ctx, 0);

    void *cursor = (void *)(long)ctx->data;
    void *frame_end = (void *)(long)ctx->data_end;

    // bpf_printk("TC egress preparse: initiated");

    int ip_type = parse_eth(&cursor, frame_end);
    if (cursor >= frame_end) 
    {
        return TC_ACT_OK;
    }
    int l4_proto = 0;
    struct hash_key h_key;
    __builtin_memset(&h_key, 0, sizeof(h_key));
    struct src_ip_add dst_ip; // dst_ip is a pod ip, inversion needed
    __builtin_memset(&dst_ip, 0, sizeof(dst_ip));

    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            h_key.src_ip.ip_v = 4;
            dst_ip.ip_v = 4;
            l4_proto = parse_ip_v4(&cursor, frame_end, &dst_ip.ip.ipv4, &h_key.src_ip.ip.ipv4);
        } 
        else 
        {
            h_key.src_ip.ip_v = 6;
            dst_ip.ip_v = 6;
            l4_proto = parse_ip_v6(&cursor, frame_end, dst_ip.ip.ipv6, h_key.src_ip.ip.ipv6, 16);
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

    bpf_printk("TC egress preparse: dns_type");
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
    struct dns_event_full *temp_event = bpf_ringbuf_reserve(&dns_event_ringbuf, sizeof(struct dns_event_full), 0);
    if (!temp_event) 
    {
        return TC_ACT_OK;
    }
    temp_event->dst_ip = dst_ip;
    struct veth_key v_key = {
        .metric_key = METRIC_PASSED,
        .src_ip = h_key.src_ip,
    };
    increment_metric(&tc_metrics_map, &v_key);
    if (dns_type == DNS_QUERY) 
    {
        v_key.metric_key = METRIC_QUERY_TO_POD;
        increment_metric(&tc_metrics_map, &v_key); 
    }
    else 
    {
        v_key.metric_key = dns_type;
        increment_metric(&tc_metrics_map, &v_key);
    }
    temp_event->src_ip = h_key.src_ip;
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
        goto discard;
    }
    cursor = (__u8 *)(cursor) + temp_event->event.qname_len;
    __u16 qname_len = (temp_event->event.qname_len + temp_event->event.compression_len) & 0xFF; 
    // there's qname_len as a cursor shift value compession_len adds up to overall qname length 
    if (qname_len == 0) 
    {
        goto discard;
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
        v_key.metric_key = METRIC_UNREGISTERED_TRAFFIC;
        increment_metric(&tc_metrics_map, &v_key); 
    }
    else 
    {
        bpf_map_delete_elem(&dns_hash_map, &h_key);
        __u64 current_time = bpf_ktime_get_ns();
        temp_event->latency_ns = current_time - *timestamp;
        temp_event->timestamp_ns = current_time;
        bpf_ringbuf_submit(temp_event, 0);
    }

    // bpf_printk("DNS event: qname=%s, type=%d", temp_event->event.qname, dns_type);

    

    return TC_ACT_OK;
    discard:
        bpf_ringbuf_discard(temp_event, 0);
        return TC_ACT_OK;
}

static __always_inline void increment_metric_xdp(void *map, __u32 index) {
    __u64 *value = bpf_map_lookup_elem(map, &index);
    if (value) {
        *value += 1;
    }
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
    struct src_ip_add buff = {};
    if (ip_type == ETH_P_IP || ip_type == ETH_P_IPV6) 
    {
        if (ip_type == ETH_P_IP) 
        {
            l4_proto = parse_ip_v4(&cursor, frame_end, &buff.ip.ipv4, &buff.ip.ipv4);
        } 
        else 
        {
            l4_proto = parse_ip_v6(&cursor, frame_end, buff.ip.ipv6, buff.ip.ipv6, 16);
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
        is_dns = xdp_parse_vxlan_from_udp(&cursor, frame_end, &buff);
        if (is_dns != DNS_YES) {
            return XDP_PASS;
        }
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
    __u32 txid = 0;
    int dns_type = parse_dns(&cursor, frame_end, &txid);
    if (dns_type == DNS_UNKNOWN) 
    {
        return XDP_PASS;
    }
    if (cursor >= frame_end) 
    {
        return XDP_PASS;
    }
    increment_metric_xdp(&xdp_metrics_map, METRIC_PASSED_XDP_DNS);
    if (dns_type == DNS_QUERY) 
    {
        increment_metric_xdp(&xdp_metrics_map, METRIC_PASSED_XDP_QUERY);
    }
    else if (dns_type == NXDOMAIN) 
    {
        increment_metric_xdp(&xdp_metrics_map, METRIC_PASSED_XDP_NXDOMAIN);
    }
    __u32 key = 0;
    __u32 *max_size = bpf_map_lookup_elem(&config_map, &key);
    if (max_size && payload_len > *max_size) 
    {
        increment_metric_xdp(&xdp_metrics_map, METRIC_ANOMALY_SIZE);
    }

    // struct dns_event_full *temp_event = bpf_map_lookup_elem(&xdp_scratchpad_map, &key);
    // if (!temp_event) 
    // {
    //     return XDP_PASS;
    // }
    // int status = parse_domain_filtered(cursor, frame_end, &temp_event->event);
    // if (status > 0) // Was the compression met?
    // {
    //     status = (status == 1) 
    //     ? parse_domain_compression(cursor, frame_end, dns_start, &temp_event->event)
    //     : status;
    //     cursor = (__u8 *)(cursor) + 2; // Move packet ptr for pointer size
    // }
    // if (status < 0) // Error occured?
    // {
    //     return XDP_PASS;
    // }
    // cursor = (__u8 *)(cursor) + temp_event->event.qname_len;
    // __u16 qname_len = temp_event->event.qname_len + temp_event->event.compression_len & 0xFF; 
    // // there's qname_len as a cursor shift value compession_len adds up to overall qname length 
    // if (qname_len == 0) 
    // {
    //     return XDP_PASS;
    // }
    // temp_event->status = dns_type;
    // temp_event->event.qname[qname_len - 1] = 0;

    // struct hash_ctx hctx = 
    // {
    //     .prime = 0x100000001b3ULL,
    //     .event = &temp_event->event,
    //     .hash = 0xcbf29ce484222325ULL,
    // };
    // bpf_loop(qname_len, hash_dns_name, &hctx, 0);

    // __u64 *timestamp = bpf_map_lookup_elem(&dns_hash_map, &key);
    // if (!timestamp) 
    // {
    //     bpf_printk("XDP: DNS event: qname=%s, type=%d. UNREG.", temp_event->event.qname, dns_type);

    bpf_printk("XDP: DNS event: type=%d", dns_type);

    return XDP_PASS;
}