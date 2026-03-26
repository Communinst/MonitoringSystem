package service

import (
	"context"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/Communinst/MonitoringSystem/internal/repository"
)

type bpfMetricsService struct {
	repo repository.BpfMetricsRepositoryIface
}

func NewBpfMetricsService(repo repository.BpfMetricsRepositoryIface) BpfMetricsServiceIface {
	return &bpfMetricsService{
		repo: repo,
	}
}

// фоновый воркер, который мы запустим в main.go
func (s *bpfMetricsService) GetMetrics(ctx context.Context) (domain.BpfMetrics, error) {
	c, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	metrics, err := s.repo.GetMetrics(c)

	return metrics, err
}
