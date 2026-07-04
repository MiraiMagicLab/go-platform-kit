// Package main demonstrates the simplest API using go-platform-kit.
// No auth, no Redis — just config, Postgres, health check, one route.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	"github.com/MiraiMagicLab/go-platform-kit/platform/health"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load(config.FromEnv())
	if err != nil {
		log.Fatal(err)
	}

	pool, err := postgres.Open(ctx, cfg.Infra.Postgres)
	if err != nil {
		log.Fatal(err)
	}
	defer postgres.Close(pool)

	logger := log.NewSlog(nil)
	router := gin.New()
	router.Use(httpx.Recovery(logger))

	checkers := []health.Checker{
		health.PostgresChecker{Pool: pool},
	}

	router.GET("/health", func(c *gin.Context) {
		statuses := health.Run(c.Request.Context(), checkers...)
		if !health.AllOK(statuses) {
			httpx.FailCode(c, http.StatusServiceUnavailable, "SERVICE_DEGRADED", statuses)
			return
		}
		httpx.OK(c, gin.H{"status": "ok"})
	})

	router.GET("/hello", func(c *gin.Context) {
		httpx.OK(c, gin.H{"message": "Hello from go-platform-kit"})
	})

	log.Printf("listening on :%s", cfg.App.Port)
	log.Fatal(router.Run(":" + cfg.App.Port))
}
