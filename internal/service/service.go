package service

import (
	"context"

	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/Communinst/MonitoringSystem/internal/repository"
)

type BpfMetricsServiceIface interface {
	GetMetrics(context.Context) (domain.BpfMetrics, error)
}

type DNSMonitorService struct {
	Metrics BpfMetricsServiceIface
}

func NewDNSMonitorService(
	repo *repository.DNSMonitorRepository,
) *DNSMonitorService {
	return &DNSMonitorService{
		Metrics: NewBpfMetricsService(repo.Metrics), 
	}
}
