package repository

import (
	"context"

	"github.com/Communinst/MonitoringSystem/internal/domain"
)

type BpfConfigRepositoryIface interface {
	UpdateThreshold(context.Context, uint32) error
}

type BpfMetricsRepositoryIface interface {
	GetMetrics(context.Context) (domain.BpfMetrics, error)
}

type DNSMonitorRepository struct {
	Conf    BpfConfigRepositoryIface
	Metrics BpfMetricsRepositoryIface // Добавили поле
}

func NewDNSMonitorRepository(
	c BpfConfigRepositoryIface,
	m BpfMetricsRepositoryIface, // Обновили конструктор
) *DNSMonitorRepository {
	return &DNSMonitorRepository{
		Conf:    c,
		Metrics: m,
	}
}
