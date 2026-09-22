package http

import (
	"net/http"
	"os"
	"path/filepath"

	"llm-proxy/internal/config"
	"llm-proxy/internal/metrics"
	"llm-proxy/internal/service"
	"llm-proxy/internal/types"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *service.Service
	cfg *config.Config
}

func NewHandler(svc *service.Service, cfg *config.Config) *Handler {
	return &Handler{svc: svc, cfg: cfg}
}

func (h *Handler) Process(c *gin.Context) {
	var req types.ProcessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload or payload_id"})
		return
	}

	opts, ok := h.resolveOptions(c)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "system is not registered or disabled"})
		return
	}

	result := h.svc.Process(req, opts)
	c.JSON(http.StatusOK, types.ProcessResponse{Result: result})
}

// resolveOptions определяет правила обработки по заголовку X-System-ID.
// При выключенном контроле доступа (по умолчанию) — маскируем всё, демаск включён.
func (h *Handler) resolveOptions(c *gin.Context) (service.ProcessOptions, bool) {
	if !h.cfg.AuthEnabled {
		return service.DefaultOptions(), true
	}

	rule, exists := h.cfg.Systems[c.GetHeader("X-System-ID")]
	if !exists || !rule.Enabled {
		return service.ProcessOptions{}, false
	}

	var maskTypes map[string]struct{}
	if len(rule.MaskTypes) > 0 {
		maskTypes = make(map[string]struct{}, len(rule.MaskTypes))
		for _, t := range rule.MaskTypes {
			maskTypes[t] = struct{}{}
		}
	}
	return service.ProcessOptions{MaskTypes: maskTypes, DemaskEnabled: rule.DemaskEnabled}, true
}

func SetupRouter(h *Handler, m *metrics.Collector) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Recovery применяется ко всем маршрутам.
	r.Use(RecoveryMiddleware())

	// /metrics регистрируется ДО metrics/ratelimit middleware, поэтому не
	// учитывается в собственных метриках и отвечает даже под перегрузкой.
	r.GET("/metrics", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.WritePrometheus(c.Writer)
	})

	r.Use(MetricsMiddleware(m))
	r.Use(RateLimitMiddleware())

	r.POST("/process", h.Process)

	frontendDir := "frontend_dist"

	if _, err := os.Stat(frontendDir); err == nil {
		r.Static("/assets", filepath.Join(frontendDir, "assets"))

		r.GET("/", func(c *gin.Context) {
			c.File(filepath.Join(frontendDir, "index.html"))
		})

		r.NoRoute(func(c *gin.Context) {
			if c.Request.Method != http.MethodGet {
				c.Status(http.StatusNotFound)
				return
			}

			c.File(filepath.Join(frontendDir, "index.html"))
		})
	}
	return r
}
