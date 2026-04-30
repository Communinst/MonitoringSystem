package handler

import (
	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfMetricsHandlerIface interface {
	Run(c *gin.Context)
}

type bpfPrometheusMetricsHandlerIface interface {
	Handler() gin.HandlerFunc
}

type DNSMonitorHandler struct {
	Prom bpfPrometheusMetricsHandlerIface
}

func NewDNSMonitorHandler(
	serv *service.DNSMonitorService,
	reg *prometheus.Registry,
) *DNSMonitorHandler {

	return &DNSMonitorHandler{
		Prom: NewBpfPrometheusMetricsHandler(reg),
	}
}
