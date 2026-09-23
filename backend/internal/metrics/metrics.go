package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	requestsTotal *prometheus.CounterVec
	tokensTotal   prometheus.Counter
	latency       *prometheus.HistogramVec
	inFlight      prometheus.Gauge
}

func New() *Metrics {
	return &Metrics{
		requestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pd_requests_total",
				Help: "Общее число обработанных запросов",
			},
			[]string{"status_code"},
		),
		tokensTotal: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "pd_tokens_total",
				Help: "Общее число обработанных токенов (~payload_bytes/4)",
			},
		),
		latency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pd_request_latency_seconds",
				Help:    "Распределение задержки обработки запроса",
				Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"status_code"},
		),
		inFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "pd_inflight_requests",
				Help: "Запросы в обработке прямо сейчас",
			},
		),
	}
}

func (m *Metrics) IncInFlight() {
	m.inFlight.Inc()
}

func (m *Metrics) DecInFlight() {
	m.inFlight.Dec()
}

// Observe фиксирует выполнение запроса.
func (m *Metrics) Observe(d time.Duration, status int, tokenCount int64) {
	statusStr := strconv.Itoa(status)

	m.requestsTotal.WithLabelValues(statusStr).Inc()
	m.latency.WithLabelValues(statusStr).Observe(d.Seconds())

	if tokenCount > 0 {
		m.tokensTotal.Add(float64(tokenCount))
	}
}
