package repository

import (
	"context"
	"fmt"
	"time"

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

func (r *bpfConfigRepository) UpdateThreshold(ctx context.Context, threshold uint32) error {
	_, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	key := uint32(0)

	if err := r.maps.ConfigMap.Update(key, threshold, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update ConfigMap in kernel: %w", err)
	}

	return nil
}
