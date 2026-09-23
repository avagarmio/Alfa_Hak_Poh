package http

import (
	"net/http"
	"sync/atomic"
	"time"

	"llm-proxy/internal/metrics"

	"github.com/gin-gonic/gin"
)

var inFlightRequests int64

const maxConcurrentRequests = 2500

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
