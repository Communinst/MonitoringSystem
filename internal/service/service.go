package service

import (
	"context"

	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/Communinst/MonitoringSystem/internal/repository"
)

type BpfConfigServiceIface interface {
	UpdateThreshold(context.Context, uint32) error
}

// НОВЫЙ интерфейс для метрик: содержит запуск фонового воркера
type BpfMetricsServiceIface interface {
	GetMetrics(context.Context) (domain.BpfMetrics, error)
}

// Агрегирующая структура сервиса
type DNSMonitorService struct {
	Conf    BpfConfigServiceIface
	Metrics BpfMetricsServiceIface // Добавили поле
}

func NewDNSMonitorService(
	repo *repository.DNSMonitorRepository,
) *DNSMonitorService {
	return &DNSMonitorService{
		Conf:    NewbpfConfigService(repo.Conf),
		Metrics: NewBpfMetricsService(repo.Metrics), // Инициализируем сервис метрик
	}
}
