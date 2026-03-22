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

type DNSMonitorHandler struct {
	Conf    bpfConfigHandlerIface
	Metrics bpfMetricsHandlerIface
}

func NewDNSMonitorHandler(
	serv *service.DNSMonitorService,
	reg *prometheus.Registry,
) *DNSMonitorHandler {

	return &DNSMonitorHandler{
		Conf:    NewbpfConfigHandler(serv.Conf),
		Metrics: NewbpfMetricsHandler(reg),
	}
}
