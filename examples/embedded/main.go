package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/authkit"
)

func main() {
	ctx := context.Background()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	jwtAccess := os.Getenv("JWT_ACCESS_SECRET")
	jwtRefresh := os.Getenv("JWT_REFRESH_SECRET")
	if jwtAccess == "" || jwtRefresh == "" {
		log.Fatal("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required")
	}

	pg, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pg.Close()

	var rdb *redis.Client
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: redisAddr})
		defer rdb.Close()
	}

	cfg := authkit.DefaultConfig()
	cfg.AuthZ = authkit.AuthZConfig{Mode: authkit.AuthZRbac}
	cfg.JWTAccessSecret = jwtAccess
	cfg.JWTRefreshSecret = jwtRefresh
	cfg.Issuer = getEnv("JWT_ISSUER", "my-embedded-app")
	cfg.AccessTokenTTL = mustDuration(getEnv("ACCESS_TOKEN_TTL", "15m"))
	cfg.RefreshTokenTTL = mustDuration(getEnv("REFRESH_TOKEN_TTL", "720h"))
	cfg.PermissionsCacheTTL = mustDuration(getEnv("PERMISSIONS_CACHE_TTL", "30s"))
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.GoogleRedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
	cfg.FacebookClientID = os.Getenv("FACEBOOK_CLIENT_ID")
	cfg.FacebookClientSecret = os.Getenv("FACEBOOK_CLIENT_SECRET")
	cfg.FacebookRedirectURL = os.Getenv("FACEBOOK_REDIRECT_URL")
	cfg.PublicBaseURL = getEnv("PUBLIC_BASE_URL", "http://localhost:8080")
	cfg.DataEncryptionKeyB64 = os.Getenv("DATA_ENCRYPTION_KEY_B64")

	// v1.1: Account lock
	cfg.MaxFailedLoginAttempts = 5
	cfg.AccountLockDuration = mustDuration(getEnv("ACCOUNT_LOCK_DURATION", "15m"))

	// v1.1: Admin bypass (admin role skips permission checks)
	cfg.AdminBypassPermission = true

	// v1.1: MFA disable requires password or code verification
	cfg.RequirePasswordForMFADisable = true

	// v1.1: OAuth cookie security (set true in production)
	cfg.OAuthCookieSecure = false

	mod, err := authkit.New(cfg, pg, rdb)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Mount all auth endpoints under /auth/*
	g := r.Group("/auth")
	mod.MountAll(g)
	mod.StartBackgroundCleanup(ctx, 30*time.Minute)

	addr := getEnv("HTTP_ADDR", ":8080")
	log.Printf("embedded app listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustDuration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid duration %q: %v", v, err)
	}
	return d
}
