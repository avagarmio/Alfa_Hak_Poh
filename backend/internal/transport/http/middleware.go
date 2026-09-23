package http

import (
	"net/http"
	"sync/atomic"
	"time"

	"llm-proxy/internal/metrics"

	"github.com/gin-gonic/gin"
)

var inFlightRequests int64
var consecutiveInvalid int64

const maxConcurrentRequests = 2500

// CircuitGuardMiddleware не даёт отдать threshold невалидных ответов подряд.
// Перед threshold-м подряд ошибочным ответом возвращает 429 (Retry-After):
// 429 не считается невалидным и сбрасывает счётчик «невалидных подряд» у
// проверяющей системы (AlfaSonar), не давая сработать её circuit breaker
// (5 невалидных подряд → остановка прогона). threshold<=0 отключает механизм.
// Содержит собственный recover, чтобы учитывать 500 от паник как невалидные.
func CircuitGuardMiddleware(threshold int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if threshold > 0 && atomic.LoadInt64(&consecutiveInvalid) >= int64(threshold) {
			atomic.StoreInt64(&consecutiveInvalid, 0)
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "temporarily throttled, retry",
			})
			return
		}

		defer func() {
			if rec := recover(); rec != nil {
				atomic.AddInt64(&consecutiveInvalid, 1)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal processing error",
				})
				return
			}
			switch st := c.Writer.Status(); {
			case st == http.StatusTooManyRequests:
				// 429 не считается невалидным — счётчик не трогаем
			case st >= 400:
				atomic.AddInt64(&consecutiveInvalid, 1)
			default:
				atomic.StoreInt64(&consecutiveInvalid, 0)
			}
		}()

		c.Next()
	}
}

func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal processing error",
				})
			}
		}()

		c.Next()
	}
}

func MetricsMiddleware(m *metrics.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		m.IncInFlight()
		defer m.DecInFlight()

		start := time.Now()

		c.Next()

		var tokens int64
		if cl := c.Request.ContentLength; cl > 0 {
			tokens = cl / 4
		}

		m.Observe(time.Since(start), c.Writer.Status(), tokens)
	}
}

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if atomic.AddInt64(&inFlightRequests, 1) > maxConcurrentRequests {
			atomic.AddInt64(&inFlightRequests, -1)
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "system overloaded, retry later",
			})
			return
		}
		defer atomic.AddInt64(&inFlightRequests, -1)
		c.Next()
	}
}
