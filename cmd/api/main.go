package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/config"
	"github.com/tienh/authsvc/internal/db"
	"github.com/tienh/authsvc/internal/handler"
	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/repository/postgres"
	"github.com/tienh/authsvc/internal/service"
	"github.com/tienh/authsvc/pkg/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pg, err := db.NewPostgresPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	rdb, err := db.NewRedis(cfg.RedisURL)
	if err != nil {
		log.Fatal(err)
	}
	if rdb != nil {
		defer rdb.Close()
	}

	userRepo := postgres.NewUserRepo(pg)
	refreshRepo := postgres.NewRefreshTokenRepo(pg)
	rbacRepo := postgres.NewRBACRepo(pg)
	identityRepo := postgres.NewIdentityRepo(pg)
	mfaRepo := postgres.NewMFARepo(pg)

	jwtm := token.NewJWTManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, "authsvc")

	var cache service.StringSliceCache = service.NoopStringSliceCache{}
	if rdb != nil {
		cache = service.NewRedisStringSliceCache(rdb)
	}
	var denylist service.AccessTokenDenylist = service.NoopAccessTokenDenylist{}
	if rdb != nil {
		denylist = service.NewRedisAccessTokenDenylist(rdb)
	}

	rbacSvc := service.NewRBACService(rbacRepo, cache, cfg.PermissionsCacheTTL)
	mfaSvc := service.NewMFAService(mfaRepo, "authsvc")
	authSvc := service.NewAuthService(userRepo, refreshRepo, mfaRepo, denylist, jwtm, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, "authsvc")

	var googleCfg *oauth2.Config
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" && cfg.GoogleRedirectURL != "" {
		googleCfg = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email"},
		}
	}
	var facebookCfg *oauth2.Config
	if cfg.FacebookClientID != "" && cfg.FacebookClientSecret != "" && cfg.FacebookRedirectURL != "" {
		facebookCfg = &oauth2.Config{
			ClientID:     cfg.FacebookClientID,
			ClientSecret: cfg.FacebookClientSecret,
			RedirectURL:  cfg.FacebookRedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.facebook.com/v21.0/dialog/oauth",
				TokenURL: "https://graph.facebook.com/v21.0/oauth/access_token",
			},
			Scopes: []string{"email"},
		}
	}
	oauthSvc := service.NewOAuthService(identityRepo, userRepo, googleCfg, facebookCfg)

	authH := handler.NewAuthHandler(authSvc, rbacSvc, userRepo)
	rbacH := handler.NewRBACHandler(rbacSvc)
	coursesH := handler.NewCoursesHandler()
	mfaH := handler.NewMFAHandler(mfaSvc)
	oauthH := handler.NewOAuthHandler(oauthSvc, authSvc, cfg.PublicBaseURL)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	r.POST("/register", authH.Register)
	r.POST("/login", authH.Login)
	r.POST("/login/2fa", authH.CompleteMFA)
	r.POST("/refresh", authH.Refresh)
	r.GET("/oauth/:provider/login", oauthH.Login)
	r.GET("/oauth/:provider/callback", oauthH.Callback)

	authMW := middleware.JWTAuth(jwtm, userRepo, func(ctx *gin.Context, jti string) (bool, error) {
		return denylist.IsDenied(ctx.Request.Context(), jti)
	})

	me := r.Group("/")
	me.Use(authMW)
	me.POST("/logout", authH.Logout)
	me.GET("/me", authH.Me)
	me.POST("/mfa/setup", mfaH.Setup)
	me.POST("/mfa/enable", mfaH.Enable)
	me.POST("/mfa/disable", mfaH.Disable)

	rbac := r.Group("/")
	rbac.Use(authMW)
	rbac.Use(middleware.RequirePermission(rbacSvc, "rbac.manage"))
	rbac.POST("/roles", rbacH.CreateRole)
	rbac.POST("/permissions", rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", rbacH.AssignRolesToUser)

	courses := r.Group("/")
	courses.Use(authMW)
	courses.Use(middleware.RequirePermission(rbacSvc, "course.create"))
	courses.POST("/courses", coursesH.CreateCourse)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	waitForShutdown()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

func waitForShutdown() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		lat := time.Since(start)
		log.Printf("%s %s %d %s", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), lat)
	}
}
