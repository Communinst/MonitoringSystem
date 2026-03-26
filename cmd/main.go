package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	bpfObj "github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/config"
	"github.com/Communinst/MonitoringSystem/internal/handler"
	prom "github.com/Communinst/MonitoringSystem/internal/prometheus"
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
	service := service.NewDNSMonitorService(repository)

	// Создаём и регистрируем коллектор Prometheus
	mappings := handler.NewMetricMappings()
	collector := prom.NewPrometheusCollector(context.Background(), service.Metrics, mappings)
	reg.MustRegister(collector)

	handler := handler.NewDNSMonitorHandler(service, reg, 512)
	router := router.NewRouter(handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srvr := server.NewServer(":8080", router.Init(), 10*time.Second, 10*time.Second)
	go func() {
		if err := srvr.Run(); err != nil {
			slog.Error("Server crash", "error", err)
			stop() // Если сервер упал сам, отменяем общий контекст
		}
	}()

	<-ctx.Done()
	slog.Info("Shutdown signal received")

	// 4. Даем 5 секунд на изящное завершение
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srvr.Shutdown(shutdownCtx); err != nil {
		slog.Error("Forced shutdown", "error", err)
	}

	slog.Info("Application exited correctly")
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
