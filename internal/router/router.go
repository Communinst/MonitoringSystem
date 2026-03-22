package router

import (
	"github.com/Communinst/MonitoringSystem/internal/handler"
	"github.com/gin-gonic/gin"
)

type Router struct {
	handler *handler.DNSMonitorHandler
}

func NewRouter(h *handler.DNSMonitorHandler) *Router {
	return &Router{handler: h}
}

func (r *Router) Init() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.GET("/metrics", r.handler.Metrics.Run)
	//router.Use(middleware...)

	// Swagger documentation route
	//router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := router.Group("/api/v1")
	{
		api.POST("/threshold", r.handler.Conf.UpdateThreshold)
	}
	return router
}
