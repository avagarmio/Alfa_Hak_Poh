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

	appCache := cache.NewShardedCache()
	svc := service.NewService(appCache)
	svc.SetCompositeMasking(cfg.CompositeMasking)
	handler := transporthttp.NewHandler(svc, cfg)
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
