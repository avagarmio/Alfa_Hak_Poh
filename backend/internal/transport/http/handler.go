package http

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"

	"llm-proxy/internal/config"
	"llm-proxy/internal/metrics"
	"llm-proxy/internal/service"
	"llm-proxy/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed openapi.yaml
var openapiSpec []byte

type Handler struct {
	svc   *service.Service
	store *config.Store
}

func NewHandler(svc *service.Service, store *config.Store) *Handler {
	return &Handler{svc: svc, store: store}
}

// ConfigGet отдаёт текущую (live) конфигурацию правил.
func (h *Handler) ConfigGet(c *gin.Context) {
	snap := h.store.Snapshot()
	c.JSON(http.StatusOK, config.Editable{
		AuthEnabled:      snap.AuthEnabled,
		CompositeMasking: snap.CompositeMasking,
		Systems:          snap.Systems,
	})
}

// ConfigPut обновляет правила в рантайме (глобальные флаги + системы).
func (h *Handler) ConfigPut(c *gin.Context) {
	var e config.Editable
	if err := c.ShouldBindJSON(&e); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config body"})
		return
	}
	h.store.Apply(e)
	h.svc.SetCompositeMasking(e.CompositeMasking) // синхронизируем сервис
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
	if !h.store.AuthEnabled() {
		return service.DefaultOptions(), true
	}

	rule, exists := h.store.System(c.GetHeader("X-System-ID"))
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
	return service.ProcessOptions{
		MaskTypes:     maskTypes,
		DemaskEnabled: rule.DemaskEnabled,
		Strategy:      rule.Strategy,
	}, true
}

func SetupRouter(h *Handler, m *metrics.Metrics) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	r.Use(RecoveryMiddleware())

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	r.GET("/openapi.yaml", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/yaml; charset=utf-8", openapiSpec)
	})

	// Live-конфигуратор правил (вне rate limit).
	r.GET("/config", h.ConfigGet)
	r.PUT("/config", h.ConfigPut)

	r.Use(MetricsMiddleware(m))
	r.Use(RateLimitMiddleware())

	r.POST("/process", CircuitGuardMiddleware(h.store.Snapshot().MaxConsecutiveErrors), h.Process)

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
