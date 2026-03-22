package handler

import (
	"net/http"

	"github.com/Communinst/MonitoringSystem/internal/service"
	"github.com/gin-gonic/gin"
)

type bpfConfigHandler struct {
	svc service.BpfConfigServiceIface
}

func NewbpfConfigHandler(svc service.BpfConfigServiceIface) *bpfConfigHandler {
	return &bpfConfigHandler{
		svc: svc,
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

	c.JSON(http.StatusOK, gin.H{
		"message":   "Threshold successfully updated",
		"threshold": req.Threshold,
	})
}
