package repository

import (
	"fmt"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/cilium/ebpf"
)

type bpfMetricsRepository struct {
	maps *bpf.BpfMaps
}

func NewBpfMetricsRepository(maps *bpf.BpfMaps) BpfMetricsRepositoryIface {
	return &bpfMetricsRepository{
		maps: maps,
	}
}

func (r *bpfMetricsRepository) GetMetrics() (passed uint64, dropped uint64, err error) {
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())

	keyPassed := uint32(0)
	if err := r.maps.MetricsMap.Lookup(&keyPassed, &perCPUValues); err != nil {
		return 0, 0, fmt.Errorf("failed to lookup passed metrics (key 0): %w", err)
	}

	for _, val := range perCPUValues {
		passed += val
	}

	keyDropped := uint32(1)
	if err := r.maps.MetricsMap.Lookup(&keyDropped, &perCPUValues); err != nil {
		return 0, 0, fmt.Errorf("failed to lookup dropped metrics (key 1): %w", err)
	}

	for _, val := range perCPUValues {
		dropped += val
	}

	return passed, dropped, nil
}
