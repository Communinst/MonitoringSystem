package main

import (
    "github.com/Communinst/MonitoringSystem/internal/prometheus"
    "github.com/Communinst/MonitoringSystem/internal/handler"
    "github.com/Communinst/MonitoringSystem/internal/domain"
    "github.com/Communinst/MonitoringSystem/internal/k8s"
    "context"
    "fmt"
    prom "github.com/prometheus/client_golang/prometheus"
)

type dummy struct{}
func (d dummy) GetMetrics(context.Context) (domain.BpfMetrics, error) {
    return domain.BpfMetrics{
        Passed: 10, AnomalySize: 5, NXDomain: 2,
        PodMetrics: map[string]*domain.PodMetric{
            "pod1": { PodMetas: k8s.PodMetadata{Namespace: "ns", Name: "po", NodeName: "no"}, NoError: 5 },
        },
    }, nil
}

func main() {
    c := prometheus.NewPrometheusCollector(context.Background(), dummy{}, handler.NewMetricMappings())
    reg := prom.NewRegistry()
    reg.MustRegister(c)
    fmt.Println("Registered successfully")
}
