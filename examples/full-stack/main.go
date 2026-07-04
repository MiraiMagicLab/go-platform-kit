// Example full-stack wires platform infra and host-owned auth HTTP handlers.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	"github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/health"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
	platformlog "github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load(config.FromEnv())
	if err != nil {
		log.Fatal(err)
	}

	pg, err := postgres.Open(ctx, cfg.Infra.Postgres)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	logger := platformlog.NewSlog(slog.Default())

	authCfg := auth.DefaultConfig()
	auth.ApplyEnv(&authCfg)
	if authCfg.Issuer == "" {
		authCfg.Issuer = cfg.App.Name
	}

	opts := []auth.Option{
		auth.WithConfig(authCfg),
		auth.WithPostgres(pg),
		auth.WithLogger(logger),
	}

	var rdb *goredis.Client
	if cfg.Infra.Redis.IsConfigured() {
		client, err := redis.Open(ctx, cfg.Infra.Redis)
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()
		rdb = client
		opts = append(opts, auth.WithRedis(client))
	}

	a, err := auth.Open(ctx, opts...)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(httpx.Recovery(logger))

	r.GET("/healthz", func(c *gin.Context) {
		checkers := []health.Checker{health.PostgresChecker{Pool: pg}}
		if rdb != nil {
			checkers = append(checkers, health.RedisChecker{Client: rdb})
		}
		statuses := health.Run(c.Request.Context(), checkers...)
		code := http.StatusOK
		if !health.AllOK(statuses) {
			code = http.StatusServiceUnavailable
		}
		c.JSON(code, gin.H{"ok": health.AllOK(statuses), "checks": statuses})
	})

	registerAuthRoutes(r.Group("/auth"), a)
	if a.GoogleOAuthConfigured() {
		a.MountReferenceOAuth(r.Group("/auth"))
		log.Printf("Google OAuth enabled (redirect: %s)", authCfg.GoogleRedirectURL)
	}
	a.StartCleanup(ctx, 30*time.Minute)

	addr := ":8080"
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		addr = v
	}
	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func registerAuthRoutes(g *gin.RouterGroup, a *auth.Auth) {
	g.POST("/register", handleRegister(a))
	g.POST("/login", handleLogin(a))
	g.POST("/refresh", handleRefresh(a))

	authed := g.Group("/")
	authed.Use(a.JWTAuth())
	authed.POST("/logout", handleLogout(a))
}

func handleRegister(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=8"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
			return
		}
		id, err := a.Register(c.Request.Context(), req.Email, req.Password)
		if err != nil {
			httpx.FailCode(c, http.StatusBadRequest, errors.CodeAuthRegisterFailed, nil)
			return
		}
		httpx.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
	}
}

func handleLogin(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
			return
		}
		res, err := a.Login(c.Request.Context(), req.Email, req.Password, auth.ClientMeta{
			IP: c.ClientIP(),
			UA: c.Request.UserAgent(),
		})
		if auth.WriteError(c, err, errors.CodeAuthInvalidCredentials, http.StatusUnauthorized) {
			return
		}
		httpx.Success(c, http.StatusOK, "success", res, nil)
	}
}

func handleRefresh(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
			return
		}
		res, err := a.Refresh(c.Request.Context(), req.RefreshToken, auth.ClientMeta{
			IP: c.ClientIP(),
			UA: c.Request.UserAgent(),
		}, "")
		if auth.WriteError(c, err, errors.CodeAuthInvalidRefresh, http.StatusUnauthorized) {
			return
		}
		httpx.Success(c, http.StatusOK, "success", res, nil)
	}
}

func handleLogout(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := auth.UserIDFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, errors.CodeUnauthorized, nil)
			return
		}
		jti, exp, ok := auth.AccessTokenMetaFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, errors.CodeUnauthorized, nil)
			return
		}
		if err := a.Logout(c.Request.Context(), userID, auth.SessionIDFromCtx(c), jti, exp); err != nil {
			httpx.FailCode(c, http.StatusInternalServerError, errors.CodeAuthLogoutFailed, nil)
			return
		}
		httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	}
}
