package repository

import (
	"context"

	"github.com/Communinst/MonitoringSystem/internal/domain"
)

type BpfMetricsRepositoryIface interface {
	GetMetrics(context.Context) (domain.BpfMetrics, error)
}

type DNSMonitorRepository struct {
	Metrics BpfMetricsRepositoryIface // Добавили поле
}

func NewDNSMonitorRepository(
	m BpfMetricsRepositoryIface, // Обновили конструктор
) *DNSMonitorRepository {
	return &DNSMonitorRepository{
		Metrics: m,
	}
}
