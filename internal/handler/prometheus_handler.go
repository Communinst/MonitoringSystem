package handler

import (
	"log/slog"

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
	globalDesc := prometheus.NewDesc(
		"bpf_dns_packets_total",
		"Total number of DNS packets processed by BPF",
		[]string{"status"},
		nil,
	)

	podDesc := prometheus.NewDesc(
		"bpf_pod_dns_activity_total",
		"Detailed DNS and traffic activity processed by BPF per pod",
		[]string{"namespace", "pod", "node", "status"},
		nil,
	)

	return []domain.MetricMapping{
		{
			Desc: globalDesc,
			ValT: prometheus.CounterValue,
			Extract: func(m *domain.BpfMetrics) []domain.MetricPoint {
				return []domain.MetricPoint{
					{Value: float64(m.Passed), Labels: []string{"passed"}},
					{Value: float64(m.AnomalySize), Labels: []string{"anomaly_size"}},
					{Value: float64(m.NXDomain), Labels: []string{"nxdomain"}},
				}
			},
		},
		{
			Desc: podDesc,
			ValT: prometheus.CounterValue,
			Extract: func(m *domain.BpfMetrics) []domain.MetricPoint {
				if len(m.PodMetrics) == 0 {
					slog.Warn("PodMetrics is empty, no pod metrics to export")
					return []domain.MetricPoint{
						{
							Value:  0,
							Labels: []string{"unknown", "unknown", "unknown", "unknown"},
						},
					}
				}
				var points []domain.MetricPoint

				for _, pm := range m.PodMetrics {
					baseLabels := []string{
						pm.PodMetas.Namespace,
						pm.PodMetas.Name,
						pm.PodMetas.NodeName,
					}

					points = append(points,
						domain.MetricPoint{Value: float64(pm.NoError), Labels: withStatus(baseLabels, "noerror")},
						domain.MetricPoint{Value: float64(pm.FormErr), Labels: withStatus(baseLabels, "formerr")},
						domain.MetricPoint{Value: float64(pm.ServFail), Labels: withStatus(baseLabels, "servfail")},
						domain.MetricPoint{Value: float64(pm.NXDomain), Labels: withStatus(baseLabels, "nxdomain")},
						domain.MetricPoint{Value: float64(pm.NotImp), Labels: withStatus(baseLabels, "notimp")},
						domain.MetricPoint{Value: float64(pm.Refused), Labels: withStatus(baseLabels, "refused")},
						domain.MetricPoint{Value: float64(pm.DnsResponseOther), Labels: withStatus(baseLabels, "dns_response_other")},
						domain.MetricPoint{Value: float64(pm.DnsQuery), Labels: withStatus(baseLabels, "dns_query")},
						domain.MetricPoint{Value: float64(pm.Passed), Labels: withStatus(baseLabels, "passed")},
						domain.MetricPoint{Value: float64(pm.AnomalySize), Labels: withStatus(baseLabels, "anomaly_size")},
						domain.MetricPoint{Value: float64(pm.PodRespond), Labels: withStatus(baseLabels, "pod_respond")},
						domain.MetricPoint{Value: float64(pm.QueryToPod), Labels: withStatus(baseLabels, "query_to_pod")},
						domain.MetricPoint{Value: float64(pm.UnregisteredTraffic), Labels: withStatus(baseLabels, "unregistered_traffic")},
					)
				}
				return points
			},
		},
	}
}

func withStatus(baseLabels []string, status string) []string {
	labels := make([]string, len(baseLabels)+1)
	copy(labels, baseLabels)
	labels[len(baseLabels)] = status
	return labels
}
