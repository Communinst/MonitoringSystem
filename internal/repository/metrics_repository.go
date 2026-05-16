package repository

import (
	"context"
	"fmt"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/cilium/ebpf"
)

const (
	noErrorKey uint32 = iota
	formErrKey
	servFailKey
	nXDomainKey
	notImpKey
	refusedKey
	dNSResponseOtherKey
	dNSQueryKey
	passKey
	anomalySizeKey
	podRespond
	queryToPod
	unregisteredResponse
	passedXdpDns
	passedXdpQuery
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
	aggPassed, err := getPassed(r)
	if err != nil {
		return domain.BpfMetrics{}, err
	}

	aggAnomalySize, err := getAnomalySize(r)
	if err != nil {
		return domain.BpfMetrics{}, err
	}

	aggNXDomain, err := getNXDomain(r)
	if err != nil {
		return domain.BpfMetrics{}, err
	}

	return domain.BpfMetrics{
		Passed:      aggPassed,
		AnomalySize: aggAnomalySize,
		NXDomain:    aggNXDomain,
	}, nil
}

func getPassed(r *bpfMetricsRepository) (uint64, error) {
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())
	if err := r.maps.XdpMetricsMap.Lookup(passedXdpDns, &perCPUValues); err != nil {
		return 0, fmt.Errorf("failed to lookup passed metrics (key 0): %w", err)
	}
	var aggPassed uint64
	for _, val := range perCPUValues {
		aggPassed += val
	}
	return aggPassed, nil
}

func getAnomalySize(r *bpfMetricsRepository) (uint64, error) {
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())
	if err := r.maps.XdpMetricsMap.Lookup(anomalySizeKey, &perCPUValues); err != nil {
		return 0, fmt.Errorf("failed to lookup anomaly size metrics (key 1): %w", err)
	}
	var aggAnomalySize uint64
	for _, val := range perCPUValues {
		aggAnomalySize += val
	}
	return aggAnomalySize, nil
}

func getNXDomain(r *bpfMetricsRepository) (uint64, error) {
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())
	if err := r.maps.XdpMetricsMap.Lookup(nXDomainKey, &perCPUValues); err != nil {
		return 0, fmt.Errorf("failed to lookup NXDomain metrics (key 2): %w", err)
	}
	var aggNXDomain uint64
	for _, val := range perCPUValues {
		aggNXDomain += val
	}
	return aggNXDomain, nil
}
