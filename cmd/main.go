package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	_ "github.com/lpernett/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promauto"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	objs, err := bootBPF()
	if err != nil {
		slog.Error("Failed to boot BPF", "error", err)
		return
	}
	defer objs.Close()

	_ = config.LoadAllEnv()
	cfg, err := config.LoadNewBootCfg()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		return
	}

	ifaceName := cfg.IfaceHookPoint.XDPIfaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		slog.Error("Failed to find interface", "interface", ifaceName, "error", err)
		return
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpWatch,
		Interface: iface.Index,
	})
	if err != nil {
		slog.Error("Failed to attach XDP", "error", err)
		return
	}
	defer l.Close()
	slog.Info("Successfully attached XDP program", "interface", ifaceName)

	configKey := uint32(0)
	maxDnsSize := uint32(512) // test

	if err := objs.ConfigMap.Update(&configKey, &maxDnsSize, 0); err != nil {
		slog.Error("Failed to update config_map", "error", err)
		return
	}
	slog.Info("Set max DNS response size", "bytes", maxDnsSize)

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

	srvr := server.NewServer(":8080", router.Init(), 10*time.Second, 10*time.Second)
	go func() {
		if err := srvr.Run(); err != nil {
			if err != http.ErrServerClosed {
				slog.Error("HTTP Server failed", "error", err)
				stop()
			}
		}
	}()

	<-ctx.Done()
	slog.Info("Shutdown signal received, initiating graceful shutdown...")

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
		log.Printf("Failed to remove memlock: %v", err)
		return bpfObj.BpfObjects{}, err
	}

	var objs bpfObj.BpfObjects
	if err := bpfObj.LoadBpfObjects(&objs, nil); err != nil {
		log.Printf("Failed to load eBPF objects: %v", err)
		return bpfObj.BpfObjects{}, err
	}
	return objs, nil
}
