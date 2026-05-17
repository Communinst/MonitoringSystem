#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>



struct src_ip_add {
    union { // 16 - выравнивание по 4 - нет
        __be32 ipv4; 
        __be32 ipv6[4]; 
    } ip;
    __u32 ip_v; // 4
}; // 20
_Static_assert(sizeof(struct src_ip_add) == 20, "src_ip_add size mismatch");

struct veth_key {
    __u32 metric_key; // 4
    struct src_ip_add src_ip; // 20
}; // 24
_Static_assert(sizeof(struct veth_key) == 24, "veth_key size mismatch");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_event_full);
    __uint(max_entries, 1);
} tc_ingress_scratchpad_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} dns_event_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 14); // 0: passed, 1: anomaly_size, 2: NXDOMAIN, 3: anomaly_unexpeceted_packet;
    __type(key, __u32);
    __type(value, __u64); // Счетчик пакетов
} xdp_metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_event_full);
    __uint(max_entries, 1);
} xdp_scratchpad_map SEC(".maps");

