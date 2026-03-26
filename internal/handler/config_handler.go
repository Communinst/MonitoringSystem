package handler

import (
	"net/http"

	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfConfigHandler struct {
	svc             service.BpfConfigServiceIface
	metricThreshold prometheus.Gauge
}

func NewbpfConfigHandler(svc service.BpfConfigServiceIface, reg *prometheus.Registry, l float64) *bpfConfigHandler {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dns_monitor_drop_threshold_bytes",
		Help: "Current minimum size of DNS response to be dropped",
	})
	reg.MustRegister(gauge)
	gauge.Set(l)

	return &bpfConfigHandler{
		svc:             svc,
		metricThreshold: gauge,
	}
}

type UpdateThresholdRequest struct {
	Threshold uint32 `json:"threshold" binding:"required,min=1"` // порог минимум 1 байт
}

func (h *bpfConfigHandler) UpdateThreshold(c *gin.Context) {
	var req UpdateThresholdRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Передаем в бизнес-логику
	if err := h.svc.UpdateThreshold(req.Threshold); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.metricThreshold.Set(float64(req.Threshold))

	c.JSON(http.StatusOK, gin.H{
		"message":   "Threshold successfully updated",
		"threshold": req.Threshold,
	})
}
