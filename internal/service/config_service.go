package service

import (
	"log"

	"github.com/Communinst/MonitoringSystem/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfConfigService struct {
	repo            repository.BpfConfigRepositoryIface
	metricThreshold prometheus.Gauge
}

func NewbpfConfigService(repo repository.BpfConfigRepositoryIface, reg *prometheus.Registry) *bpfConfigService {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dns_monitor_drop_threshold_bytes",
		Help: "Current minimum size of DNS response to be dropped",
	})

	reg.MustRegister(gauge)

	return &bpfConfigService{
		repo:            repo,
		metricThreshold: gauge,
	}
}

func (s *bpfConfigService) UpdateThreshold(threshold uint32) error {
	if err := s.repo.UpdateThreshold(threshold); err != nil {
		return err
	}

	s.metricThreshold.Set(float64(threshold))
	log.Printf("Service: successfully updated drop threshold to %d bytes", threshold)

	return nil
}
