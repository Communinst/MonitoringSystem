package domain

import (
	"net"

	"github.com/Communinst/MonitoringSystem/internal/k8s"
)

type BpfMetrics struct {
	Passed      uint64
	AnomalySize uint64
	NXDomain    uint64

	PodMetrics map[string]*PodMetric
}

type PodMetric struct {
	PodMetas            k8s.PodMetadata
	NoError             uint64 // 0
	FormErr             uint64 // 1
	ServFail            uint64 // 2
	NXDomain            uint64 // 3
	NotImp              uint64 // 4
	Refused             uint64 // 5
	DnsResponseOther    uint64 // 6
	DnsQuery            uint64 // 7
	Passed              uint64 // 8
	AnomalySize         uint64 // 9
	PodRespond          uint64 // 10
	QueryToPod          uint64 // 11
	UnregisteredTraffic uint64 // 12
}

type BpfVethKey struct {
	MetricKey uint32   // 4 bytes
	SrcIP     [16]byte // 16 bytes: covers the C union { __be32 ipv4; __be32 ipv6[4]; }
	IPVersion uint32   // 4 bytes: 4 for IPv4, 6 for IPv6
}

func (k *BpfVethKey) IPString() string {
	if k.IPVersion == 4 {
		return net.IP(k.SrcIP[:4]).String()
	} else if k.IPVersion == 6 {
		return net.IP(k.SrcIP[:16]).String()
	}
	return "unknown"
}
