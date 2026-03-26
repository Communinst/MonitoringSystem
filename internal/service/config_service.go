package service

import (
	"context"
	"log"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/repository"
)

type bpfConfigService struct {
	repo repository.BpfConfigRepositoryIface
}

func NewbpfConfigService(repo repository.BpfConfigRepositoryIface) *bpfConfigService {
	return &bpfConfigService{
		repo: repo,
	}
}

func (s *bpfConfigService) UpdateThreshold(ctx context.Context, threshold uint32) error {
	c, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	if err := s.repo.UpdateThreshold(c, threshold); err != nil {
		return err
	}
	log.Printf("Service: successfully updated drop threshold to %d bytes", threshold)

	return nil
}
