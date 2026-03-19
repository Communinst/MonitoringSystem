package main

// [flag for generate command] [go run] [path]        [archi tecture] [file prefix]  [bpf file path] --(those are inner clang instructions) [include file path] [verifier optimization]
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ../bpf/dns_monitor.c -- -I./bpf/include -O2 -g -Wall

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/config"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	_ "github.com/lpernett/godotenv"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promauto"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// if err := config.LoadAllEnv(); err != nil {
	// 	return
	// }
	_ = config.LoadAllEnv()
	
	cfg, err := config.LoadNewBootCfg()
	if err != nil {
		return
	}
	// Cloud native environment is more used to virtual interfaces, probably should be replaced
	ifaceName := cfg.HookPoint.HookIfaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpWatch,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer l.Close()
	log.Printf("Successfully attached XDP program to %s", ifaceName)

	configKey := uint32(0)
	maxDnsSize := uint32(512) // test

	if err := objs.ConfigMap.Update(&configKey, &maxDnsSize, 0); err != nil {
		log.Fatalf("Failed to update config_map: %v", err)
	}
	log.Printf("Set max DNS response size to %d bytes", maxDnsSize)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for packets... (Press Ctrl+C to exit)")

	for {
		select {
		case <-ticker.C:
			printMetrics(objs.MetricsMap)
		case <-stopper:
			log.Println("Exiting and detaching eBPF program...")
			return
		}
	}
}

// PERCPU return array value by core
func printMetrics(metricsMap *ebpf.Map) {
	keys := []uint32{0, 1}
	names := []string{"PASSED", "DROPPED"}

	for i, key := range keys {
		var perCPUValues []uint64
		if err := metricsMap.Lookup(&key, &perCPUValues); err != nil {
			log.Printf("Error reading metric %s: %v", names[i], err)
			continue
		}

		var total uint64 = 0
		for _, val := range perCPUValues {
			total += val
		}

		if total > 0 {
			log.Printf("Metric [%s]: %d packets", names[i], total)
		}
	}
}
