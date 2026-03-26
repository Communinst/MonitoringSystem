package service

import (
	"log"

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

func (s *bpfConfigService) UpdateThreshold(threshold uint32) error {
	if err := s.repo.UpdateThreshold(threshold); err != nil {
		return err
	}
	log.Printf("Service: successfully updated drop threshold to %d bytes", threshold)

	return nil
}
