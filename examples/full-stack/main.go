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
	platformlog "github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/health"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
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
	auth.ApplyEnv(&cfg)
	cfg.JWTAccessSecret = infraCfg.Auth.JWTAccessSecret
	cfg.JWTRefreshSecret = infraCfg.Auth.JWTRefreshSecret
	cfg.DataEncryptionKeyB64 = infraCfg.Auth.DataEncryptionKeyB64
	cfg.GoogleClientID = infraCfg.Auth.GoogleClientID
	cfg.GoogleClientSecret = infraCfg.Auth.GoogleClientSecret
	cfg.GoogleRedirectURL = infraCfg.Auth.GoogleRedirectURL
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = infraCfg.Auth.PublicBaseURL
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = getenv("PUBLIC_BASE_URL", "http://localhost:8080")
	}
	if cfg.FrontendBaseURL == "" {
		cfg.FrontendBaseURL = infraCfg.Auth.FrontendBaseURL
	}
	if cfg.FrontendBaseURL == "" {
		cfg.FrontendBaseURL = cfg.PublicBaseURL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = getenv("JWT_ISSUER", "my-app")
	}
	auth.ApplyEnv(&cfg)

	opts := []auth.Option{
		auth.WithConfig(cfg),
		auth.WithPostgres(pg),
		auth.WithLogger(platformlog.NewSlog(slog.Default())),
	}
	var rdb *goredis.Client
	if infraCfg.Infra.Redis.IsConfigured() {
		client, err := redis.Open(ctx, infraCfg.Infra.Redis)
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
	r.Use(httpx.Recovery())

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
		log.Printf("Google OAuth enabled (redirect: %s)", cfg.GoogleRedirectURL)
	}
	a.StartCleanup(ctx, 30*time.Minute)

	addr := getenv("HTTP_ADDR", ":8080")
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

type registerReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func handleRegister(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerReq
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
			return
		}
		id, err := a.Register(c.Request.Context(), req.Email, req.Password)
		if err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthRegisterFailed, nil)
			return
		}
		httpx.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
	}
}

type loginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func handleLogin(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
			return
		}
		res, err := a.Login(c.Request.Context(), req.Email, req.Password, auth.ClientMeta{
			IP: c.ClientIP(),
			UA: c.Request.UserAgent(),
		})
		if auth.WriteError(c, err, httpx.CodeAuthInvalidCredentials, http.StatusUnauthorized) {
			return
		}
		httpx.Success(c, http.StatusOK, "success", res, nil)
	}
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func handleRefresh(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshReq
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
			return
		}
		res, err := a.Refresh(c.Request.Context(), req.RefreshToken, auth.ClientMeta{
			IP: c.ClientIP(),
			UA: c.Request.UserAgent(),
		}, "")
		if auth.WriteError(c, err, httpx.CodeAuthInvalidRefresh, http.StatusUnauthorized) {
			return
		}
		httpx.Success(c, http.StatusOK, "success", res, nil)
	}
}

func handleLogout(a *auth.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := auth.UserIDFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			return
		}
		jti, exp, ok := auth.AccessTokenMetaFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			return
		}
		if err := a.Logout(c.Request.Context(), userID, auth.SessionIDFromCtx(c), jti, exp); err != nil {
			httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeAuthLogoutFailed, nil)
			return
		}
		httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
