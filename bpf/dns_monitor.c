
// +build ignore

#include "include/vmlinux.h"
#include "include/if_ether.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum
{
    DNS_REQUEST = 0,
    DNS_ANSWER = 1,
};


static __always_inline int parse_eth(void **cursor, void const *end) {
    struct ethhdr *eth = *cursor; // Assuming Eth frame accepted

    if ((void *)(eth + 1) > end) {
        return -1; // frame corrupted
    }

    // Parse type
    long eth_type = bpf_ntohs(eth->h_proto);
    *cursor = (void*)eth + 1;

    // 802.1AD
    if (eth_type == ETH_P_8021AD) {
        struct vlan_hdr *ad = *cursor;
        if ((void *)ad > end) {
            return -1; // frame corrupted
        }
        eth_type = bpf_ntohs(ad->h_vlan_encapsulated_proto);
        *cursor = (void*)ad + 1;
    }  

    // 802.1Q
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *ad = *cursor;
        if ((void *)ad > end) {
            return -1; // frame corrupted
        }
        eth_type = bpf_ntohs(ad->h_vlan_encapsulated_proto);
        *cursor = (void*)ad + 1;
    }
    else {
        return -1; // frame type isn't supported
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

static __always_inline int parse_udp_for_dns(void **cursor, void *end) {

    struct udphdr *udp = *cursor;

    if ((void*)(udp + 1) > end) {
        return -1;
    }

    int src_port = bpf_htohs(udp->source);
    int dest_port = bpf_htohs(udp->dest);

    *cursor = (void *)(udp + 1);

    if (src_port == dest_port) {
        return -1;
    }

    if (src_port == 53) {
        return DNS_REQUEST;
    } 
    else if (dest_port == 53){
        return DNS_ANSWER;
    }

    return -1;
}

SEC("xdp")
int dns_watch(struct xdp_md *ctx) { // Supports VLANs and default eth frame
    // Ethernet-Packet-UDP-DnsRequest
    void *cursor = (void *)(long)ctx->data; // Cursor pattern allows to decrease amount of ctx mem approaches
    void *frame_end = (void *)(long)ctx->data_end;

    int ip_type = parse_eth(&cursor, frame_end);
    if (ip_type < 0) {
        return XDP_PASS;
    }

    // IPv4
    int udp_proto = 0;
    if (ip_type == ETH_P_IP) {
        udp_proto = parse_ip_v4(cursor, frame_end);
    }
    else {
        return XDP_PASS;
    }
    
    // Only UDP accepted
    if (udp_proto != IPPROTO_UDP) { 
        return XDP_PASS;
    }

    int dns_type = parse_udp_for_dns(cursor, frame_end);

    // Drop everything different from DNS
    if (dns_type < 0) {
        return XDP_PASS;
    }

    if (dns_type == DNS_REQUEST) {
        // REQUEST strategy
    }
    else if (dns_type == DNS_ANSWER) {
        // ASNWER strategy
    }

    return XDP_PASS;
 }