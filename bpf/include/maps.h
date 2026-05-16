#pragma once
#include "../linux/vmlinux.h"
#include <bpf/bpf_helpers.h>



struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 14);
    __type(key, __u32);
    __type(value, __u64); // Сntr
} tc_metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_event_xdp);
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
    __type(value, struct dns_event_xdp);
    __uint(max_entries, 1);
} xdp_scratchpad_map SEC(".maps");

