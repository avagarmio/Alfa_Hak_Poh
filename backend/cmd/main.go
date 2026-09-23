package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"llm-proxy/internal/config"
	"llm-proxy/internal/metrics"
	"llm-proxy/internal/repository/cache"
	"llm-proxy/internal/service"
	transporthttp "llm-proxy/internal/transport/http"
)

func main() {
	cfg := config.Load()

	// Выбор хранилища: Redis (общее, для горизонтального масштабирования) или
	// in-memory. При недоступности Redis — безопасный фолбэк на память.
	var store service.Store
	if cfg.CacheBackend == "redis" {
		if rs, err := cache.NewRedisStore(cfg.RedisAddr); err != nil {
			log.Printf("Redis (%s) недоступен: %v — используем in-memory кэш", cfg.RedisAddr, err)
			store = cache.NewShardedCache()
		} else {
			log.Printf("Кэш: Redis %s", cfg.RedisAddr)
			store = rs
		}
	} else {
		store = cache.NewShardedCache()
	}

	svc := service.NewService(store)
	svc.SetCompositeMasking(cfg.CompositeMasking)
	cfgStore := config.NewStore(cfg)
	handler := transporthttp.NewHandler(svc, cfgStore)
	mc := metrics.New()
	router := transporthttp.SetupRouter(handler, mc)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	go func() {
		log.Printf("Server listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Graceful shutdown initiated...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped")
}
