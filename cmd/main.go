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

	"github.com/prometheus/client_golang/prometheus"
)

const (
	configMapKey uint32 = 0
)

func main() {
	// prepare sygnal context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	//
	objs, err := bootBPF()
	if err != nil {
		slog.Error("Failed to boot BPF", "error", err)
		return
	}
	defer objs.Close()

	// Supports both - k8s and local deployment
	_ = config.LoadAllEnv()
	cfg, err := config.LoadNewBootCfg()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		return
	}

	// specify hook. High probability of rewriting
	ifaceName := cfg.BPF.XDPIfaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		slog.Error("Failed to find interface", "interface", ifaceName, "error", err)
		return
	}

	// target specific hook. High probability of rewriting
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpWatch,
		Interface: iface.Index,
	})
	if err != nil {
		slog.Error("Failed to attach XDP", "error", err)
		return
	}
	defer l.Close()

	// Set max DNS response size in config map. High probability of rewriting
	maxDnsSize := uint32(cfg.BPF.MaxDnsSize)
	if err := objs.ConfigMap.Update(configMapKey, &maxDnsSize, 0); err != nil {
		slog.Error("Failed to update config_map", "error", err)
		return
	}
	slog.Info("Set max DNS response size", "bytes", maxDnsSize)

	// Setup layers and router. High probability of rewriting
	router := setupLayers(&objs.BpfMaps)

	// Http server setup with graceful shutdown. High probability of rewriting
	srvr := server.NewServer(cfg.HTTPServer.Address, router.Init(), 10*time.Second, 10*time.Second)
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

	// Graceful shutdown mechanism. High probability of rewriting
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srvr.Shutdown(shutdownCtx); err != nil {
		slog.Error("Forced shutdown", "error", err)
	}

	slog.Info("Application exited correctly")
}

func setupLayers(b *bpfObj.BpfMaps) *router.Router {
	metricsRepo := repository.NewBpfMetricsRepository(b)
	repository := repository.NewDNSMonitorRepository(metricsRepo)
	service := service.NewDNSMonitorService(repository)
	reg := prometheusSetup(service)
	handler := handler.NewDNSMonitorHandler(service, reg)
	return router.NewRouter(handler)
}

func prometheusSetup(svc *service.DNSMonitorService) *prometheus.Registry {
	mappings := handler.NewMetricMappings()
	collector := prom.NewPrometheusCollector(context.Background(), svc.Metrics, mappings)
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)
	return reg
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
