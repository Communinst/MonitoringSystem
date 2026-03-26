package domain

import (
	"github.com/prometheus/client_golang/prometheus"
)

type MetricPoint struct {
	Value  float64
	Labels []string
}

type MetricMapping struct {
	Desc    *prometheus.Desc
	ValT    prometheus.ValueType
	Extract func(m *BpfMetrics) []MetricPoint
}
