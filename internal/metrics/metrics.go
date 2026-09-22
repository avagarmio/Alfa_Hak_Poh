// Package metrics собирает технические метрики обработки (Latency, RPS, TPS)
// и экспортирует их в текстовом формате Prometheus. Значения ПД сюда не попадают.
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// latencyBuckets — верхние границы бакетов гистограммы задержки, секунды.
// Сгущены вокруг ориентира ТЗ (Latency ≤ 1 с).
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Collector потокобезопасен: все счётчики атомарны, рассчитан на конкурентную
// нагрузку 1000+ RPS без блокировок.
type Collector struct {
	startTime       time.Time
	requests        atomic.Int64
	latencySumNanos atomic.Int64
	tokens          atomic.Int64
	errors5xx       atomic.Int64
	rateLimited     atomic.Int64
	inFlight        atomic.Int64
	buckets         []atomic.Int64 // len = len(latencyBuckets)+1 (последний — +Inf)
}

func New() *Collector {
	return &Collector{
		startTime: time.Now(),
		buckets:   make([]atomic.Int64, len(latencyBuckets)+1),
	}
}

func (c *Collector) IncInFlight() { c.inFlight.Add(1) }
func (c *Collector) DecInFlight() { c.inFlight.Add(-1) }

// Observe фиксирует один обработанный запрос: задержку, HTTP-статус и число
// токенов (оценка 1 токен ≈ 4 байта payload).
func (c *Collector) Observe(d time.Duration, status int, tokenCount int64) {
	c.requests.Add(1)
	c.latencySumNanos.Add(d.Nanoseconds())
	if tokenCount > 0 {
		c.tokens.Add(tokenCount)
	}
	switch {
	case status == 429:
		c.rateLimited.Add(1)
	case status >= 500:
		c.errors5xx.Add(1)
	}

	sec := d.Seconds()
	idx := len(latencyBuckets)
	for i, b := range latencyBuckets {
		if sec <= b {
			idx = i
			break
		}
	}
	c.buckets[idx].Add(1)
}

// WritePrometheus печатает метрики в формате Prometheus text exposition.
func (c *Collector) WritePrometheus(w io.Writer) {
	uptime := time.Since(c.startTime).Seconds()
	req := c.requests.Load()
	tok := c.tokens.Load()
	sumNanos := c.latencySumNanos.Load()

	writeCounter(w, "pd_requests_total", "Общее число обработанных запросов", req)
	writeCounter(w, "pd_tokens_total", "Общее число обработанных токенов (~payload_bytes/4)", tok)
	writeCounter(w, "pd_errors_5xx_total", "Число ответов 5xx", c.errors5xx.Load())
	writeCounter(w, "pd_rate_limited_total", "Число ответов 429", c.rateLimited.Load())
	writeGauge(w, "pd_inflight_requests", "Запросы в обработке прямо сейчас", float64(c.inFlight.Load()))
	writeGauge(w, "pd_uptime_seconds", "Аптайм процесса, секунды", uptime)

	var avgRPS, avgTPS, avgLatency float64
	if uptime > 0 {
		avgRPS = float64(req) / uptime
		avgTPS = float64(tok) / uptime
	}
	if req > 0 {
		avgLatency = float64(sumNanos) / float64(req) / 1e9
	}
	writeGauge(w, "pd_avg_rps", "Средний RPS с момента старта", avgRPS)
	writeGauge(w, "pd_avg_tps", "Средний TPS (tokens per second) с момента старта", avgTPS)
	writeGauge(w, "pd_avg_latency_seconds", "Средняя задержка запроса, секунды", avgLatency)

	fmt.Fprintln(w, "# HELP pd_request_latency_seconds Распределение задержки обработки запроса")
	fmt.Fprintln(w, "# TYPE pd_request_latency_seconds histogram")
	cum := int64(0)
	for i, b := range latencyBuckets {
		cum += c.buckets[i].Load()
		fmt.Fprintf(w, "pd_request_latency_seconds_bucket{le=\"%g\"} %d\n", b, cum)
	}
	cum += c.buckets[len(latencyBuckets)].Load()
	fmt.Fprintf(w, "pd_request_latency_seconds_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "pd_request_latency_seconds_sum %f\n", float64(sumNanos)/1e9)
	fmt.Fprintf(w, "pd_request_latency_seconds_count %d\n", req)
}

func writeCounter(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

func writeGauge(w io.Writer, name, help string, v float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
}
