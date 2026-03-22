package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type bpfMetricsHandler struct {
	svc gin.HandlerFunc
}

func NewbpfMetricsHandler(reg *prometheus.Registry) *bpfMetricsHandler {
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	return &bpfMetricsHandler{
		svc: gin.WrapH(promHandler),
	}
}

func (h *bpfMetricsHandler) Run(c *gin.Context) {
	h.svc(c)
}
