package handler

import (
	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfConfigHandlerIface interface {
	UpdateThreshold(c *gin.Context)
}

type bpfMetricsHandlerIface interface {
	Run(c *gin.Context)
}

type bpfPrometheusMetricsHandlerIface interface {
	Handler() gin.HandlerFunc
}

type DNSMonitorHandler struct {
	Conf bpfConfigHandlerIface
	Prom bpfPrometheusMetricsHandlerIface
}

func NewDNSMonitorHandler(
	serv *service.DNSMonitorService,
	reg *prometheus.Registry,
	l float64,
) *DNSMonitorHandler {

	return &DNSMonitorHandler{
		Conf: NewbpfConfigHandler(serv.Conf, reg, l),
		Prom: NewBpfPrometheusMetricsHandler(reg),
	}
}
