// Package metrics exposes Prometheus metrics for LinkGuard Cloud.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric collectors.
type Metrics struct {
	// Interface traffic
	InterfaceRxBytes *prometheus.GaugeVec
	InterfaceTxBytes *prometheus.GaugeVec
	InterfaceRxPkts  *prometheus.GaugeVec
	InterfaceTxPkts  *prometheus.GaugeVec

	// System
	CPUPercent    prometheus.Gauge
	MemPercent    prometheus.Gauge
	DiskPercent   prometheus.Gauge
	UptimeSeconds prometheus.Gauge

	// Service
	ServiceUptime prometheus.Gauge
	AlertsTotal   prometheus.Gauge
}

// New registers and returns all Prometheus metrics.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)

	return &Metrics{
		InterfaceRxBytes: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_rx_bytes_total",
			Help:      "Total bytes received on the interface",
		}, []string{"interface"}),

		InterfaceTxBytes: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_tx_bytes_total",
			Help:      "Total bytes transmitted on the interface",
		}, []string{"interface"}),

		InterfaceRxPkts: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_rx_packets_total",
			Help:      "Total packets received on the interface",
		}, []string{"interface"}),

		InterfaceTxPkts: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "interface_tx_packets_total",
			Help:      "Total packets transmitted on the interface",
		}, []string{"interface"}),

		CPUPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_cpu_percent",
			Help:      "Current CPU usage percentage",
		}),

		MemPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_memory_percent",
			Help:      "Current memory usage percentage",
		}),

		DiskPercent: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_disk_percent",
			Help:      "Current disk usage percentage (root filesystem)",
		}),

		UptimeSeconds: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "system_uptime_seconds",
			Help:      "System uptime in seconds",
		}),

		ServiceUptime: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "service_uptime_seconds",
			Help:      "LinkGuard Cloud service uptime in seconds",
		}),

		AlertsTotal: f.NewGauge(prometheus.GaugeOpts{
			Namespace: "linkguard",
			Name:      "alerts_unresolved_total",
			Help:      "Number of unresolved alerts",
		}),
	}
}
