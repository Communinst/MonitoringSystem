package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	configMapKey uint32 = 0
)

func main() {
	// Excessive if Kernel 5.11+ used, but still's a good practice.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed to remove memlock: %v", err)
	}

	// prepare signal context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	//
	objs, err := bootBPF()
	if err != nil {
		slog.Error("Failed to boot BPF", "error", err)
		return
	}
	defer objs.Close()

	// Supports both - orchestrated and local deployment
	_ = config.LoadAllEnv()
	cfg, err := config.LoadNewBootCfg()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		return
	}

	// Specify hook. High probability of rewriting
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

	//
	router := router.NewRouter(setupLayers(&objs.BpfMaps))

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

func setupLayers(b *bpfObj.BpfMaps) *handler.DNSMonitorHandler {
	metricsRepo := repository.NewBpfMetricsRepository(b)
	repo := repository.NewDNSMonitorRepository(metricsRepo)
	serv := service.NewDNSMonitorService(repo)
	reg := prometheusSetup(serv)
	return handler.NewDNSMonitorHandler(serv, reg)
}

func prometheusSetup(svc *service.DNSMonitorService) *prometheus.Registry {
	mappings := handler.NewMetricMappings()
	collector := prom.NewPrometheusCollector(context.Background(), svc.Metrics, mappings)
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)
	return reg
}

func bootBPF() (bpfObj.BpfObjects, error) {

	var objs bpfObj.BpfObjects
	if err := bpfObj.LoadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1024 * 1024 * 2, // 5 MB для логов верификатора
			LogLevel:     ebpf.LogLevelInstruction | ebpf.LogLevelBranch,
		},
	}); err != nil {
		log.Printf("Failed to load eBPF objects: %v", err)
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Это выведет полный лог в консоль!
			fmt.Printf("Verifier Error Log:\n%+v\n", ve)
		}
		return bpfObj.BpfObjects{}, err
	}
	return objs, nil
}
