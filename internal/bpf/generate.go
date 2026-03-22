package bpf

// [flag for generate command] [go run] [path]        [archi tecture] [file prefix]  [bpf file path] --(those are inner clang instructions) [include file path] [verifier optimization]
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 Bpf ../../bpf/dns_monitor.c -- -I./bpf/include -O2 -g -Wall
