package http

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

// Перед 5-м (threshold=4) подряд ошибочным ответом должен вернуться 429.
func TestCircuitGuardInserts429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	atomic.StoreInt64(&consecutiveInvalid, 0)

	r := gin.New()
	r.GET("/x", CircuitGuardMiddleware(4), func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "boom"})
	})

	var got []int
	for i := 0; i < 6; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/x", nil)
		r.ServeHTTP(w, req)
		got = append(got, w.Code)
	}

	want := []int{500, 500, 500, 500, 429, 500}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("последовательность статусов %v, ожидалось %v", got, want)
		}
	}
}

// Паника в обработчике учитывается как невалидный ответ (500) и тоже попадает
// под защиту (5-й подряд → 429).
func TestCircuitGuardCountsPanics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	atomic.StoreInt64(&consecutiveInvalid, 0)

	r := gin.New()
	r.GET("/p", CircuitGuardMiddleware(4), func(c *gin.Context) {
		panic("kaboom")
	})

	var got []int
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/p", nil)
		r.ServeHTTP(w, req)
		got = append(got, w.Code)
	}
	// 4 паники → 500, пятый запрос → 429
	if got[4] != http.StatusTooManyRequests {
		t.Fatalf("после 4 паник ожидался 429, получено %v", got)
	}
}
