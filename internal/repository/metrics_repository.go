package repository

import (
	"context"
	"fmt"

	"github.com/Communinst/MonitoringSystem/internal/bpf"
	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/Communinst/MonitoringSystem/internal/k8s"
	"github.com/cilium/ebpf"
)

const (
	metricNoErrorKey uint32 = iota
	metricFormErrKey
	metricServFailKey
	metricNXDomainKey
	metricNotImpKey
	metricRefusedKey
	metricDNSResponseOtherKey
	metricDNSQueryKey
	metricPassKey
	metricAnomalySizeKey
	metricPodRespondKey
	metricQueryToPodkey
	metricUnregisteredTrafficKey
	metricMaxIndex
)

const (
	metricPassedXdpDnsKey uint32 = iota
	metricPassedXdpAnomalySizeKey
	metricPassedXdpQueryKey
	metricPassedXdpNXDomainKey
	metricPassedXdpMaxIndexKey
)

type IPResolver interface {
	GetByIP(ip string) k8s.PodMetadata
}

type bpfMetricsRepository struct {
	maps     *bpf.BpfMaps
	resolver IPResolver
}

func NewBpfMetricsRepository(maps *bpf.BpfMaps, resolver IPResolver) BpfMetricsRepositoryIface {
	return &bpfMetricsRepository{
		maps:     maps,
		resolver: resolver,
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

	podMetrics, err := getTcMetrics(r)
	if err != nil {
	
		podMetrics = make(map[string]*domain.PodMetric)
	}

	return domain.BpfMetrics{
		Passed:      aggPassed,
		AnomalySize: aggAnomalySize,
		NXDomain:    aggNXDomain,
		PodMetrics:  podMetrics,
	}, nil
}

func getPassed(r *bpfMetricsRepository) (uint64, error) {
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU())
	if err := r.maps.XdpMetricsMap.Lookup(metricPassedXdpDnsKey, &perCPUValues); err != nil {
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
	if err := r.maps.XdpMetricsMap.Lookup(metricPassedXdpAnomalySizeKey, &perCPUValues); err != nil {
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
	if err := r.maps.XdpMetricsMap.Lookup(metricPassedXdpNXDomainKey, &perCPUValues); err != nil {
		return 0, fmt.Errorf("failed to lookup NXDomain metrics (key 2): %w", err)
	}
	var aggNXDomain uint64
	for _, val := range perCPUValues {
		aggNXDomain += val
	}
	return aggNXDomain, nil
}

func getTcMetrics(r *bpfMetricsRepository) (map[string]*domain.PodMetric, error) {
	podMetrics := make(map[string]*domain.PodMetric)

	var key domain.BpfVethKey
	perCPUValues := make([]uint64, ebpf.MustPossibleCPU()) // percpu values from map

	iter := r.maps.TcMetricsMap.Iterate()
	for iter.Next(&key, &perCPUValues) {
		ipStr := key.IPString()

		var sum uint64
		for _, v := range perCPUValues {
			sum += v
		}

		if sum == 0 {
			continue
		}

		var podMetas k8s.PodMetadata
		if r.resolver != nil {
			podMetas = r.resolver.GetByIP(ipStr)
		}
		if podMetas.Name == "" {
			podMetas.Name = "unknown"
			podMetas.Namespace = "unknown"
			podMetas.NodeName = "unknown"
		}

		pm, exists := podMetrics[podMetas.Name]
		if !exists {
			pm = &domain.PodMetric{
				PodMetas: podMetas,
			}
			podMetrics[podMetas.Name] = pm
		}

		switch key.MetricKey {
		case metricNoErrorKey:
			pm.NoError += sum
		case metricFormErrKey:
			pm.FormErr += sum
		case metricServFailKey:
			pm.ServFail += sum
		case metricNXDomainKey:
			pm.NXDomain += sum
		case metricNotImpKey:
			pm.NotImp += sum
		case metricRefusedKey:
			pm.Refused += sum
		case metricDNSResponseOtherKey:
			pm.DnsResponseOther += sum
		case metricDNSQueryKey:
			pm.DnsQuery += sum
		case metricPassKey:
			pm.Passed += sum
		case metricAnomalySizeKey:
			pm.AnomalySize += sum
		case metricPodRespondKey:
			pm.PodRespond += sum
		case metricQueryToPodkey:
			pm.QueryToPod += sum
		case metricUnregisteredTrafficKey:
			pm.UnregisteredTraffic += sum
		}
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tc_metrics_map: %w", err)
	}

	return podMetrics, nil
}
