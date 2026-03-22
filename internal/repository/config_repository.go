package repository

import (
	"fmt"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/cilium/ebpf"
)


type bpfConfigRepository struct {
	maps *bpf.BpfMaps
}

func NewbpfConfigRepository(maps *bpf.BpfMaps) *bpfConfigRepository {
	return &bpfConfigRepository{
		maps: maps,
	}
}

func (r *bpfConfigRepository) UpdateThreshold(threshold uint32) error {
	key := uint32(0)

	if err := r.maps.ConfigMap.Update(key, threshold, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update ConfigMap in kernel: %w", err)
	}

	return nil
}
