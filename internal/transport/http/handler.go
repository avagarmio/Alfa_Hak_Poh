package http

import (
	"net/http"

	"llm-proxy/internal/service"
	"llm-proxy/internal/types"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *service.Service
}

func NewHandler(svc *service.Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Process(c *gin.Context) {
	var req types.ProcessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload or payload_id"})
		return
	}

	result := h.svc.Process(req)
	c.JSON(http.StatusOK, types.ProcessResponse{Result: result})
}

func SetupRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(RecoveryMiddleware())

	r.POST("/process", h.Process)
	return r
}
