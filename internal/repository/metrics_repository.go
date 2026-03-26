package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/cilium/ebpf"
)

const (
	passKey uint16 = 0
	dropKey uint16 = 1
)

type bpfMetricsRepository struct {
	maps *bpf.BpfMaps
}

func NewBpfMetricsRepository(maps *bpf.BpfMaps) BpfMetricsRepositoryIface {
	return &bpfMetricsRepository{
		maps: maps,
	}
}

func (r *bpfMetricsRepository) GetMetrics(ctx context.Context) (domain.BpfMetrics, error) {
	_, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())

	keyPassed := uint32(passKey)
	if err := r.maps.MetricsMap.Lookup(&keyPassed, &perCPUValues); err != nil {
		return domain.BpfMetrics{}, fmt.Errorf("failed to lookup passed metrics (key 0): %w", err)
	}

	var aggPassed, aggDropped uint64
	for _, val := range perCPUValues {
		aggPassed += val
	}

	keyDropped := uint32(dropKey)
	if err := r.maps.MetricsMap.Lookup(&keyDropped, &perCPUValues); err != nil {
		return domain.BpfMetrics{}, fmt.Errorf("failed to lookup dropped metrics (key 1): %w", err)
	}

	for _, val := range perCPUValues {
		aggDropped += val
	}

	return domain.BpfMetrics{
		Passed:  aggPassed,
		Dropped: aggDropped,
	}, nil
}
