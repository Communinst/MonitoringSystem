
// // +build ignore

// #include "include/vmlinux.h"
// #include "include/if_ether.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>
// #include <linux/pkt_cls.h>

// #define DNS_PORT 53
// #define MAX_EXTENSION_HEADER_COUNT 5
// #define MAX_QNAME_LEN 255
// #define MAX_LABEL_COUNT 10
// #define MAX_LABEL_LEN 63 
// #define MAX_DNS_OFFSET 4096 



// char LICENSE[] SEC("license") = "GPL";

// enum packet_status {
//     PACKET_CORRUPTED = -1,
//     PACKET_OK = 0,
// };

// enum is_DNS 
// {
    
//     DNS_NO = 0,
//     DNS_YES = 1,
// };

// enum dns_packet_type
// {
//     DNS_UNKNOWN = -1,
//     DNS_QUERY = 0,
//     DNS_RESPONSE_OK = 1,
//     DNS_RESPONSE_NXDOMAIN = 2,
//     DNS_RESPONSE_OTHER = 3,
// };

// enum ip_frag {
//     FRAG_SUBSEQUENT = -2, 
//     FRAG_HEAD = 0,
// };

// enum label_status {
//     LABEL_ERR = -1,
//     LABEL_OK = 0,
//     LABEL_DONE = 1,
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, __u32);
// } config_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 3); // 0: passed, 1: dropped, 2: NXDOMAIN;
//     __type(key, __u32);
//     __type(value, __u64); // Счетчик пакетов
// } metrics_map SEC(".maps");

// struct dnshdr {
//     __u16 id;
//     __u16 flags;
//     __u16 qdcount;
//     __u16 ancount;
//     __u16 nscount;
//     __u16 arcount;
// };

// struct dns_event {
//     __u16 dns_type;
//     __u16 qname_len;
//     __u8 qname[MAX_QNAME_LEN];
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 20); // 1 MB buffer for events (~4000 concurrent events capacity)
// } events_ringbuf SEC(".maps");


// static __always_inline void increment_metric(__u32 index) {
//     __u64 *value = bpf_map_lookup_elem(&metrics_map, &index);
//     if (value) {
//         *value += 1;
//     }
// }

// static __always_inline long parse_eth(void **cursor, void const *end) {
//     struct ethhdr *eth = *cursor; // Assuming Eth frame accepted

//     if ((void *)(eth + 1) > end) {
//         return PACKET_CORRUPTED; // frame corrupted
//     }

//     // Здесь используем bpf_ntohs (Network to Host Short), 
//     // чтобы привести значение к локальному порядку байт узла.
//     long l3_proto = bpf_ntohs(eth->h_proto);
//     *cursor = (void *)(eth + 1);

//     return l3_proto;
// }

// static __always_inline int parse_ipv4(void **cursor, void const *end) {
//     struct iphdr *ip = *cursor;

//     if ((void *)(ip + 1) > end) {
//         return PACKET_CORRUPTED; // frame corrupted
//     }

//     *cursor = (void *)ip + ip->ihl * 4; // Move cursor to the end of IP header
//     if (*cursor > end) 
//     {
//         return PACKET_CORRUPTED;
//     }

//     return ip->protocol; // Return L4 protocol (TCP, UDP, etc.)
// }

// static __always_inline int parse_ipv6(void **cursor, void const *end) {
//     struct ipv6hdr *ip6 = *cursor;
//     if ((void *)(ip6 + 1) > end) {
//         return PACKET_CORRUPTED;
//     }
//     *cursor = (void *)(ip6 + 1);
//     __u8 next_hdr = ip6->nexthdr;

//     for (int i = 0; i < MAX_EXTENSION_HEADER_COUNT; i++) 
//     {
//         if (next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP) 
//         {
//             return next_hdr; 
//         }

//         if (next_hdr == 44) 
//         {
//             struct ipv6_opt_hdr *eh = *cursor;
//             if ((void *)(eh + 1) > end) 
//             {
//                 return PACKET_CORRUPTED;
//             }
//             next_hdr = eh->nexthdr;
//             *cursor = (void *)((__u8 *)(*cursor) +  8);
//         } 
//         else if (next_hdr == 0 || next_hdr == 60 || next_hdr == 43 || next_hdr == 51 || next_hdr == 50)  
//         {
//             struct ipv6_opt_hdr *eh = *cursor;
//             if ((void *)(eh + 1) > end) 
//             {
//                 return PACKET_CORRUPTED;
//             }
//             next_hdr = eh->nexthdr; // w/o fragment header
//             int hdr_bytes = (eh->hdrlen + 1) * 8;
            
//             *cursor = (void *)((__u8 *)(*cursor) + hdr_bytes);
//         }
//         else 
//         {
//             return PACKET_CORRUPTED;
//         }

//         if (*cursor > end) 
//         {
//             return PACKET_CORRUPTED; 
//         }

//     }
//     if (next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP) 
//     {
//         return next_hdr; 
//     }
//     return PACKET_CORRUPTED; // Too many extension headers, treat as corrupted
// }


// static __always_inline int parse_ip(void **cursor, void const *end, long l3_proto) {
//     switch (l3_proto) 
//     {
//         case ETH_P_IP: 
//         {
//             return parse_ipv4(cursor, end);
//         }
//         case ETH_P_IPV6: 
//         {
//             return parse_ipv6(cursor, end);
//         }
//         default:
//             return -1; // Unsupported L3 protocol
//     }
// }

// static __always_inline int parse_udp_for_dns(void **cursor, void const *end, long l4_proto) {
//     struct udphdr *udp = *cursor;

//     if ((void*)(udp + 1) > end) {
//         return DNS_NO;
//     }

//     int src_port = bpf_ntohs(udp->source);
//     int dest_port = bpf_ntohs(udp->dest);
//     if (dest_port == DNS_PORT || src_port == DNS_PORT) 
//     {
//         *cursor = (void *)(udp + 1); // Move cursor to the end of UDP header
//         if (*cursor > end) {
//             return DNS_NO;
//         }
//         return DNS_YES;
//     }
//     else 
//     {
//         return PACKET_CORRUPTED
//     }
// }

// static __always_inline int parse_tcp_for_dns(void **cursor, void const *end, long l4_proto) {

// }

// static __always_inline int parse_dns(void **cursor, void const *end, long l4_proto) {
//     switch (l4_proto) 
//     {
//         case IPPROTO_UDP: 
//         {
//             struct udphdr *udp = *cursor;
//             if ((void *)(udp + 1) > end) {
//                 return PACKET_CORRUPTED;
//             }
//             *cursor = (void *)(udp + 1); 
//             break;
//         }
//         case IPPROTO_TCP: 
//         {
//             struct tcphdr *tcp = *cursor;
//             if ((void *)(tcp + 1) > end) {
//                 return PACKET_CORRUPTED;
//             }
//             int tcp_hdr_len = tcp->doff * 4;
//             if (tcp_hdr_len < sizeof(struct tcphdr)) {
//                 return PACKET_CORRUPTED; // Invalid TCP header length
//             }
//             *cursor = (void *)tcp + tcp_hdr_len; // Move cursor to the end of TCP header
//             break;
//         }
//         default:
//             return -1; // Unsupported L4 protocol
//     }
// }

// SEC("tc")
// int tc_watch(struct __sk_buff *ctx) {
//     void *cursor = (void *)(long)ctx->data;
//     void *end = (void *)(long)ctx->data_end;
    
//     long l3_proto = parse_eth(&cursor, end);
//     long l4_proto = parse_ip(&cursor, end, l3_proto);
//     long dns_result = parse_dns(&cursor, end, l4_proto);

//     struct udphdr *udp = cursor;
//     if ((void *)(udp + 1) > end) return TC_ACT_OK;
    
//     // Проверяем, что это DNS (порт 53)
//     if (udp->source != bpf_htons(53) && udp->dest != bpf_htons(53)) {
//         return 0;
//     }
//     cursor += sizeof(struct udphdr);

//     struct dnshdr *dns = cursor;
//     if ((void *)(dns + 1) > end) return 0;
//     cursor += sizeof(struct dnshdr);

//     // Выделяем память в Ring Buffer
//     struct dns_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct dns_event), 0);
//     if (!event) return 0; // Нет места в буфере

//     event->dns_type = dns->flags;
//     event->qname_len = 0;

//     // Парсинг QNAME (ограничиваем циклы для BPF-верификатора)
//     #pragma unroll
//     for (int i = 0; i < MAX_LABEL_COUNT; i++) {
//         __u8 *len_byte = cursor;
//         if ((void *)(len_byte + 1) > end) break;
        
//         __u8 label_len = *len_byte;
//         if (label_len == 0) break; // Конец доменного имени
        
//         cursor++; // Пропускаем байт длины
        
//         #pragma unroll
//         for (int j = 0; j < MAX_LABEL_LEN; j++) {
//             if (j >= label_len) break;
            
//             __u8 *c = cursor;
//             if ((void *)(c + 1) > end) goto send_event;
            
//             if (event->qname_len < MAX_QNAME_LEN - 1) {
//                 event->qname[event->qname_len] = *c;
//                 event->qname_len++;
//             }
//             cursor++;
//         }
        
//         // Добавляем точку между лейблами
//         if (event->qname_len < MAX_QNAME_LEN - 1) {
//             event->qname[event->qname_len] = '.';
//             event->qname_len++;
//         }
//     }

// send_event:
//     if (event->qname_len > 0 && event->qname[event->qname_len - 1] == '.') {
//         event->qname_len--; // Убираем последнюю точку
//     }
    
//     bpf_ringbuf_submit(event, 0);
//     increment_metric(0); // Например, считаем обработанные пакеты

//     return 0; // TC_ACT_OK (пропускаем пакет дальше)
// }