package service

import (
	"context"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
)

type BpfConfigServiceIface interface {
	UpdateThreshold(threshold uint32) error
}

// НОВЫЙ интерфейс для метрик: содержит запуск фонового воркера
type BpfMetricsServiceIface interface {
	StartCollector(ctx context.Context, interval time.Duration)
}

// Агрегирующая структура сервиса
type DNSMonitorService struct {
	Conf    BpfConfigServiceIface
	Metrics BpfMetricsServiceIface // Добавили поле
}

func NewDNSMonitorService(
	repo *repository.DNSMonitorRepository, // Обрати внимание: лучше передавать указатель
	reg *prometheus.Registry,
) *DNSMonitorService {
	return &DNSMonitorService{
		Conf:    NewbpfConfigService(repo.Conf),
		Metrics: NewBpfMetricsService(repo.Metrics, reg), // Инициализируем сервис метрик
	}
}
