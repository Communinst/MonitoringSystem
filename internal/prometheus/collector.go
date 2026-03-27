package prometheus

import (
	"context"
	"time"

	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusCollector struct {
	ctx      context.Context
	mappings []domain.MetricMapping // Turn to map. 1 Metrics - 1 FQname
	svc      service.BpfMetricsServiceIface
}

func NewPrometheusCollector(
	c context.Context,
	svc service.BpfMetricsServiceIface,
	mappings []domain.MetricMapping,
) *PrometheusCollector {
	return &PrometheusCollector{
		ctx:      c,
		svc:      svc,
		mappings: mappings,
	}
}

func (c *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.mappings {
		ch <- m.Desc
	}
}

func (c *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {

	ct, cancel := context.WithTimeout(c.ctx, time.Second*10)
	defer cancel()

	metrics, err := c.svc.GetMetrics(ct)
	if err != nil {
		return // или логирование
	}
	for _, mapping := range c.mappings {
		points := mapping.Extract(&metrics)
		for _, p := range points {
			ch <- prometheus.MustNewConstMetric(
				mapping.Desc, mapping.ValT, p.Value, p.Labels...,
			)
		}
	}
}
