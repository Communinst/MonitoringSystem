package main

import (
	"context"
	"log"
	"net"
	"time"

	bpfObj "github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/config"
	"github.com/Communinst/MonitoringSystem/internal/handler"
	"github.com/Communinst/MonitoringSystem/internal/repository"
	"github.com/Communinst/MonitoringSystem/internal/router"
	"github.com/Communinst/MonitoringSystem/internal/server"
	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	_ "github.com/lpernett/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promauto"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	objs, err := bootBPF()
	if err != nil {
		return
	}
	defer objs.Close()

	_ = config.LoadAllEnv()
	cfg, err := config.LoadNewBootCfg()
	if err != nil {
		return
	}

	ifaceName := cfg.IfaceHookPoint.XDPIfaceName
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

	// -------------------------
	reg := prometheus.NewRegistry()
	confRepo := repository.NewbpfConfigRepository(&objs.BpfMaps)
	metricsRepo := repository.NewBpfMetricsRepository(&objs.BpfMaps)

	repository := repository.NewDNSMonitorRepository(confRepo, metricsRepo)
	service := service.NewDNSMonitorService(repository, reg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запускаем сборщик метрик каждые 2 секунды
	go service.Metrics.StartCollector(ctx, 2*time.Second)

	handler := handler.NewDNSMonitorHandler(service, reg, 512)
	router := router.NewRouter(handler)

	server := server.NewServer(":8080", router.Init(), 10*time.Second, 10*time.Second)
	server.Run()
	// ---

}

func bootBPF() (bpfObj.BpfObjects, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
		return bpfObj.BpfObjects{}, err
	}

	var objs bpfObj.BpfObjects
	if err := bpfObj.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
		return bpfObj.BpfObjects{}, err
	}
	return objs, nil
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
