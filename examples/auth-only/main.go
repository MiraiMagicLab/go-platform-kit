// Package main demonstrates auth wiring using go-platform-kit.
// Shows register, login, refresh, logout, and protected routes.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	"github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
	platformlog "github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/pagination"
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

	logger := platformlog.NewSlog(nil)

	authCfg := auth.DefaultConfig()
	auth.ApplyEnv(&authCfg)
	authCfg.Issuer = cfg.App.Name

	a, err := auth.Open(ctx,
		auth.WithConfig(authCfg),
		auth.WithPostgres(pool),
		auth.WithLogger(logger),
	)
	if err != nil {
		log.Fatal(err)
	}

	a.StartBackgroundCleanup(ctx, 0)

	r := gin.New()
	r.Use(httpx.Recovery(logger))

	api := r.Group("/api/v1")

	api.GET("/health", func(c *gin.Context) {
		httpx.OK(c, gin.H{"status": "ok"})
	})

	authGroup := api.Group("/auth")
	{
		authGroup.POST("/register", func(c *gin.Context) {
			var req struct {
				Email    string `json:"email" binding:"required,email"`
				Password string `json:"password" binding:"required,min=8"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
				return
			}
			id, err := a.Register(c.Request.Context(), req.Email, req.Password)
			if auth.WriteError(c, err, errors.CodeAuthRegisterFailed, http.StatusConflict) {
				return
			}
			httpx.Created(c, gin.H{"id": id})
		})

		authGroup.POST("/login", func(c *gin.Context) {
			var req struct {
				Email    string `json:"email" binding:"required,email"`
				Password string `json:"password" binding:"required"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
				return
			}
			result, err := a.Login(c.Request.Context(), req.Email, req.Password, auth.ClientMeta{
				IP: c.ClientIP(), UA: c.Request.UserAgent(),
			})
			if auth.WriteError(c, err, errors.CodeAuthInvalidCredentials, http.StatusUnauthorized) {
				return
			}
			httpx.OK(c, result)
		})

		authGroup.POST("/refresh", func(c *gin.Context) {
			var req struct {
				RefreshToken string `json:"refresh_token" binding:"required"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				httpx.FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)
				return
			}
			result, err := a.Refresh(c.Request.Context(), req.RefreshToken, auth.ClientMeta{
				IP: c.ClientIP(), UA: c.Request.UserAgent(),
			}, "")
			if auth.WriteError(c, err, errors.CodeAuthInvalidRefresh, http.StatusUnauthorized) {
				return
			}
			httpx.OK(c, result)
		})
	}

	private := api.Group("")
	private.Use(a.JWTAuth())
	{
		private.GET("/me", func(c *gin.Context) {
			userID, _ := auth.UserIDFromCtx(c)
			profile, err := a.GetProfile(c.Request.Context(), userID)
			if err != nil {
				httpx.FailCode(c, http.StatusInternalServerError, errors.CodeInternal, nil)
				return
			}
			httpx.OK(c, profile)
		})

		admin := private.Group("/admin")
		admin.Use(a.RequireRole("admin"))
		{
			admin.GET("/users", func(c *gin.Context) {
				users, total, _ := a.ListUsers(c.Request.Context(), 1, 20, auth.ListUsersFilter{})
				httpx.Success(c, http.StatusOK, errors.CodeSuccess, pagination.Result{
					Records: users,
					Pagination: pagination.Meta{
						Limit:  20,
						Offset: 0,
						Total:  int64(total),
					},
				}, nil)
			})
		}
	}

	log.Printf("listening on :%s", cfg.App.Port)
	log.Fatal(r.Run(":" + cfg.App.Port))
}
