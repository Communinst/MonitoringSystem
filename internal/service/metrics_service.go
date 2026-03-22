package service

import (
	"context"
	"log"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfMetricsService struct {
	repo          repository.BpfMetricsRepositoryIface
	metricPassed  prometheus.Gauge
	metricDropped prometheus.Gauge
}

func NewBpfMetricsService(repo repository.BpfMetricsRepositoryIface, reg *prometheus.Registry) BpfMetricsServiceIface {
	passed := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dns_monitor_passed_packets_total",
		Help: "Total number of passed DNS packets",
	})
	dropped := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dns_monitor_dropped_packets_total",
		Help: "Total number of dropped DNS packets",
	})

	// Регистрируем в нашем кастомном Registry
	reg.MustRegister(passed, dropped)

	return &bpfMetricsService{
		repo:          repo,
		metricPassed:  passed,
		metricDropped: dropped,
	}
}

// фоновый воркер, который мы запустим в main.go
func (s *bpfMetricsService) StartCollector(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Metrics collector started with interval %v", interval)

	for {
		select {
		case <-ctx.Done():
			log.Println("Metrics collector stopped")
			return
		case <-ticker.C:
			passed, dropped, err := s.repo.GetMetrics()
			if err != nil {
				log.Printf("Metrics Service error: failed to get metrics: %v", err)
				continue
			}

			s.metricPassed.Set(float64(passed))
			s.metricDropped.Set(float64(dropped))
		}
	}
}
