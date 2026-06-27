// Example full-stack wires shared platform infrastructure and mounts the auth capability.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	platformlog "github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

func main() {
	ctx := context.Background()
	infraCfg, err := config.Load(config.FromEnv())
	if err != nil {
		log.Fatal(err)
	}
	if infraCfg.Auth.JWTAccessSecret == "" || infraCfg.Auth.JWTRefreshSecret == "" {
		log.Fatal("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required")
	}

	pg, err := postgres.Open(ctx, infraCfg.Infra.Postgres)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	cfg := auth.DefaultConfig()
	cfg.JWTAccessSecret = infraCfg.Auth.JWTAccessSecret
	cfg.JWTRefreshSecret = infraCfg.Auth.JWTRefreshSecret
	cfg.DataEncryptionKeyB64 = infraCfg.Auth.DataEncryptionKeyB64
	cfg.PublicBaseURL = getenv("PUBLIC_BASE_URL", "http://localhost:8080")
	cfg.Issuer = getenv("JWT_ISSUER", "my-app")

	opts := []auth.Option{
		auth.WithConfig(cfg),
		auth.WithPostgres(pg),
		auth.WithLogger(platformlog.NewSlog(slog.Default())),
	}
	if infraCfg.Infra.Redis.IsConfigured() {
		rdb, err := redis.Open(ctx, infraCfg.Infra.Redis)
		if err != nil {
			log.Fatal(err)
		}
		defer rdb.Close()
		opts = append(opts, auth.WithRedis(rdb))
	}

	mod, err := auth.New(ctx, opts...)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	g := r.Group("/auth")
	mod.MountAll(g)
	mod.StartBackgroundCleanup(ctx, 30*time.Minute)

	addr := getenv("HTTP_ADDR", ":8080")
	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
