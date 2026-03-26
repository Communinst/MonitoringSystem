package handler

import (
	"github.com/Communinst/MonitoringSystem/internal/domain"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type bpfPrometheusMetricsHandler struct {
	ginHandler gin.HandlerFunc
}

func NewBpfPrometheusMetricsHandler(reg *prometheus.Registry) bpfPrometheusMetricsHandlerIface {
	stdHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})

	return &bpfPrometheusMetricsHandler{
		ginHandler: gin.WrapH(stdHandler),
	}
}

func (h *bpfPrometheusMetricsHandler) Handler() gin.HandlerFunc {
	return h.ginHandler
}

func NewMetricMappings() []domain.MetricMapping {
	desc := prometheus.NewDesc(
		"bpf_dns_packets_total",
		"Total number of DNS packets processed by BPF",
		[]string{"status"},
		nil,
	)

	return []domain.MetricMapping{
		{
			Desc: desc,
			ValT: prometheus.CounterValue,
			Extract: func(m *domain.BpfMetrics) []domain.MetricPoint {
				return []domain.MetricPoint{
					{Value: float64(m.Passed), Labels: []string{"passed"}},
					{Value: float64(m.Dropped), Labels: []string{"dropped"}},
				}
			},
		},
	}
}
