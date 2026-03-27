package authkit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/tienh/authsvc/internal/handler"
	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/repository/postgres"
	"github.com/tienh/authsvc/internal/security"
	"github.com/tienh/authsvc/internal/service"
	"github.com/tienh/authsvc/pkg/token"
)

type Config struct {
	JWTAccessSecret     string
	JWTRefreshSecret    string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	PermissionsCacheTTL time.Duration
	Issuer              string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	FacebookClientID     string
	FacebookClientSecret string
	FacebookRedirectURL  string

	PublicBaseURL string
	// 32-byte key encoded in base64 for encrypting sensitive data (e.g. TOTP secret).
	DataEncryptionKeyB64 string

	// Dynamic RBAC bootstrap from host project.
	SeedRoles           []string
	SeedPermissions     []string
	SeedRolePermissions map[string][]string // role -> []permission names

	RateLimitLoginPerMinute   int
	RateLimitRefreshPerMinute int
	RateLimitForgotPerMinute  int
	CORSAllowedOrigins        []string

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     720 * time.Hour,
		PermissionsCacheTTL: 30 * time.Second,
		Issuer:              "authkit",
		PublicBaseURL:       "http://localhost:8080",
		SeedRoles:           []string{"admin", "user"},
		SeedPermissions:     []string{"rbac.manage"},
		SeedRolePermissions: map[string][]string{
			"admin": {"rbac.manage"},
		},
		RateLimitLoginPerMinute:   20,
		RateLimitRefreshPerMinute: 60,
		RateLimitForgotPerMinute:  10,
		CORSAllowedOrigins:        []string{"*"},
		SMTPPort:                  587,
	}
}

type Module struct {
	authH  *handler.AuthHandler
	rbacH  *handler.RBACHandler
	mfaH   *handler.MFAHandler
	oauthH *handler.OAuthHandler

	authMW  gin.HandlerFunc
	rbacSvc *service.RBACService
	cleanup *service.CleanupService
	redis   *redis.Client
	cfg     Config
}

func New(cfg Config, pg *pgxpool.Pool, redisClient *redis.Client) (*Module, error) {
	if pg == nil {
		return nil, errors.New("pgx pool is required")
	}
	if cfg.JWTAccessSecret == "" || cfg.JWTRefreshSecret == "" {
		return nil, errors.New("JWT access/refresh secrets are required")
	}
	if cfg.AccessTokenTTL <= 0 || cfg.RefreshTokenTTL <= 0 {
		return nil, errors.New("token TTL must be > 0")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "authkit"
	}
	if err := seedRBAC(context.Background(), pg, cfg); err != nil {
		return nil, err
	}

	userRepo := postgres.NewUserRepo(pg)
	refreshRepo := postgres.NewRefreshTokenRepo(pg)
	rbacRepo := postgres.NewRBACRepo(pg)
	identityRepo := postgres.NewIdentityRepo(pg)
	mfaRepo := postgres.NewMFARepo(pg)
	auditRepo := postgres.NewAuditRepo(pg)
	emailTokenRepo := postgres.NewEmailTokenRepo(pg)

	jwtm := token.NewJWTManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.Issuer)

	var permCache service.StringSliceCache = service.NoopStringSliceCache{}
	var denylist service.AccessTokenDenylist = service.NoopAccessTokenDenylist{}
	if redisClient != nil {
		permCache = service.NewRedisStringSliceCache(redisClient)
		denylist = service.NewRedisAccessTokenDenylist(redisClient)
	}

	var mfaCipher *security.StringCipher
	if cfg.DataEncryptionKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.DataEncryptionKeyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid DataEncryptionKeyB64: %w", err)
		}
		mfaCipher, err = security.NewStringCipher(key)
		if err != nil {
			return nil, err
		}
	}

	rbacSvc := service.NewRBACService(rbacRepo, permCache, cfg.PermissionsCacheTTL)
	userAdminSvc := service.NewUserAdminService(userRepo, refreshRepo)
	mfaSvc := service.NewMFAService(mfaRepo, cfg.Issuer, mfaCipher)
	auditSvc := service.NewAuditService(auditRepo)
	cleanupSvc := service.NewCleanupService(refreshRepo, mfaRepo, emailTokenRepo)

	var sender service.EmailSender
	if cfg.SMTPHost != "" && cfg.SMTPUser != "" && cfg.SMTPPass != "" && cfg.SMTPFrom != "" {
		sender = service.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)
	}
	emailSvc := service.NewEmailService(userRepo, emailTokenRepo, refreshRepo, sender, cfg.PublicBaseURL)
	authSvc := service.NewAuthService(
		userRepo,
		refreshRepo,
		mfaRepo,
		mfaSvc,
		denylist,
		jwtm,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		cfg.Issuer,
	)

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

	authH := handler.NewAuthHandler(authSvc, emailSvc, rbacSvc, userRepo, auditSvc)
	rbacH := handler.NewRBACHandler(rbacSvc, userAdminSvc)
	mfaH := handler.NewMFAHandler(mfaSvc, auditSvc)
	oauthH := handler.NewOAuthHandler(oauthSvc, authSvc, cfg.PublicBaseURL)

	authMW := middleware.JWTAuth(jwtm, userRepo, func(ctx *gin.Context, jti string) (bool, error) {
		return denylist.IsDenied(ctx.Request.Context(), jti)
	})

	return &Module{
		authH:   authH,
		rbacH:   rbacH,
		mfaH:    mfaH,
		oauthH:  oauthH,
		authMW:  authMW,
		rbacSvc: rbacSvc,
		cleanup: cleanupSvc,
		redis:   redisClient,
		cfg:     cfg,
	}, nil
}

// Mount registers auth/rbac/mfa/oauth routes into an existing Gin router/group.
func (m *Module) Mount(r gin.IRouter) {
	r.Use(middleware.RequestID())
	r.Use(middleware.AccessLog())
	r.Use(simpleCORS(m.cfg.CORSAllowedOrigins))

	memLimiter := middleware.NewInMemoryRateLimiter()
	loginLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:login", m.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:refresh", m.cfg.RateLimitRefreshPerMinute, time.Minute)
	forgotLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:forgot", m.cfg.RateLimitForgotPerMinute, time.Minute)

	r.POST("/register", m.authH.Register)
	r.POST("/login", loginLimit, m.authH.Login)
	r.POST("/login/2fa", m.authH.CompleteMFA)
	r.POST("/refresh", refreshLimit, m.authH.Refresh)
	r.POST("/password/forgot", forgotLimit, m.authH.ForgotPassword)
	r.POST("/password/reset", m.authH.ResetPassword)
	r.POST("/email/verify/confirm", m.authH.ConfirmVerifyEmail)
	r.GET("/oauth/:provider/login", m.oauthH.Login)
	r.GET("/oauth/:provider/callback", m.oauthH.Callback)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/logout", m.authH.Logout)
	me.GET("/me", m.authH.Me)
	me.POST("/mfa/setup", m.mfaH.Setup)
	me.POST("/mfa/enable", m.mfaH.Enable)
	me.POST("/mfa/disable", m.mfaH.Disable)
	me.POST("/email/verify/request", m.authH.RequestVerifyEmail)

	rbac := r.Group("/")
	rbac.Use(m.authMW)
	rbac.Use(middleware.RequirePermission(m.rbacSvc, "rbac.manage"))
	rbac.POST("/roles", m.rbacH.CreateRole)
	rbac.POST("/permissions", m.rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
	rbac.POST("/users/:id/ban", m.rbacH.BanUser)
	rbac.POST("/users/:id/unban", m.rbacH.UnbanUser)
}

func (m *Module) StartBackgroundCleanup(ctx context.Context, interval time.Duration) {
	if m.cleanup == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	tk := time.NewTicker(interval)
	go func() {
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				m.cleanup.RunOnce(ctx)
			}
		}
	}()
}

func simpleCORS(allowedOrigins []string) gin.HandlerFunc {
	allowAll := len(allowedOrigins) == 0
	allowed := map[string]struct{}{}
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
		if o == "*" {
			allowAll = true
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (allowAll || containsOrigin(allowed, origin)) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-Id")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		}
		if strings.EqualFold(c.Request.Method, http.MethodOptions) {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func containsOrigin(allowed map[string]struct{}, origin string) bool {
	_, ok := allowed[origin]
	return ok
}

func seedRBAC(ctx context.Context, pg *pgxpool.Pool, cfg Config) error {
	for _, role := range cfg.SeedRoles {
		if role == "" {
			continue
		}
		if _, err := pg.Exec(ctx, `insert into roles (name) values ($1) on conflict (name) do nothing`, role); err != nil {
			return fmt.Errorf("seed role %q: %w", role, err)
		}
	}
	for _, perm := range cfg.SeedPermissions {
		if perm == "" {
			continue
		}
		if _, err := pg.Exec(ctx, `insert into permissions (name) values ($1) on conflict (name) do nothing`, perm); err != nil {
			return fmt.Errorf("seed permission %q: %w", perm, err)
		}
	}
	for role, perms := range cfg.SeedRolePermissions {
		if role == "" {
			continue
		}
		for _, perm := range perms {
			if perm == "" {
				continue
			}
			if _, err := pg.Exec(ctx, `
				insert into role_permissions (role_id, permission_id)
				select r.id, p.id
				from roles r
				join permissions p on p.name = $2
				where r.name = $1
				on conflict do nothing
			`, role, perm); err != nil {
				return fmt.Errorf("seed role_permission %q->%q: %w", role, perm, err)
			}
		}
	}
	return nil
}
