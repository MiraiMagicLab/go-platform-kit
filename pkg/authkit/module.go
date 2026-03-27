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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/MiraiMagicLab/go-auth-lib/internal/handler"
	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/internal/repository/postgres"
	"github.com/MiraiMagicLab/go-auth-lib/internal/security"
	"github.com/MiraiMagicLab/go-auth-lib/internal/service"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/token"
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

	// Permission required to access RBAC admin endpoints. Default: "rbac.manage".
	RBACAdminPermission string

	// RequireEmailVerifiedBeforeLogin prevents issuing tokens until user's email is verified.
	RequireEmailVerifiedBeforeLogin bool

	RateLimitLoginPerMinute              int
	RateLimitRefreshPerMinute            int
	RateLimitForgotPerMinute             int
	RateLimitPasswordResetPerMinute      int
	RateLimitEmailVerifyConfirmPerMinute int
	CORSAllowedOrigins                   []string

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	Hooks Hooks
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
		RBACAdminPermission:                  "rbac.manage",
		RequireEmailVerifiedBeforeLogin:      false,
		RateLimitLoginPerMinute:              20,
		RateLimitRefreshPerMinute:            60,
		RateLimitForgotPerMinute:             10,
		RateLimitPasswordResetPerMinute:      10,
		RateLimitEmailVerifyConfirmPerMinute: 10,
		CORSAllowedOrigins:                   []string{"*"},
		SMTPPort:                             587,
	}
}

type Module struct {
	authH  *handler.AuthHandler
	rbacH  *handler.RBACHandler
	mfaH   *handler.MFAHandler
	oauthH *handler.OAuthHandler

	authMW        gin.HandlerFunc
	rbacSvc       *service.RBACService
	cleanup       *service.CleanupService
	redis         *redis.Client
	cfg           Config
	commonMounted bool
}

// AuthMiddleware returns the JWT auth middleware for protecting host app routes.
// Usage: `r.GET("/path", mod.AuthMiddleware(), handler)`
func (m *Module) AuthMiddleware() gin.HandlerFunc { return m.authMW }

// RequirePermission returns a middleware that checks a dynamic RBAC permission string.
// Usage: `r.GET("/path", mod.AuthMiddleware(), mod.RequirePermission("vocab.read"), handler)`
func (m *Module) RequirePermission(permission string) gin.HandlerFunc {
	return middleware.RequirePermission(m.rbacSvc, permission)
}

// RequireRBACAdmin returns a middleware that checks `cfg.RBACAdminPermission` (default: "rbac.manage").
func (m *Module) RequireRBACAdmin() gin.HandlerFunc {
	return middleware.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission)
}

// UserIDFromCtx exposes the authenticated user id from Gin context (set by AuthMiddleware()).
func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) { return middleware.UserIDFromCtx(c) }

// AccessTokenMetaFromCtx exposes access token metadata (jti, exp) from Gin context (set by AuthMiddleware()).
func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	return middleware.AccessTokenMetaFromCtx(c)
}

// MountOptions provides fine-grained control over which endpoints are mounted.
type MountOptions struct {
	Common bool
	Auth   AuthEndpoints
	Email  EmailEndpoints
	MFA    MFAEndpoints
	OAuth  bool
	RBAC   RBACEndpoints
}

type AuthEndpoints struct {
	Register bool
	Login    bool
	Login2FA bool
	Refresh  bool
	Logout   bool
	Me       bool
}

type EmailEndpoints struct {
	ForgotPassword      bool
	ResetPassword       bool
	VerifyConfirmPublic bool
	VerifyRequestAuthed bool
}

type MFAEndpoints struct {
	Setup   bool
	Enable  bool
	Disable bool
}

type RBACEndpoints struct {
	ManageRoles       bool
	ManagePermissions bool
	AssignRolePerms   bool
	AssignUserRoles   bool
	BanUser           bool
	UnbanUser         bool
}

func DefaultMountOptions() MountOptions {
	return MountOptions{
		Common: true,
		Auth: AuthEndpoints{
			Register: true,
			Login:    true,
			Login2FA: true,
			Refresh:  true,
			Logout:   true,
			Me:       true,
		},
		Email: EmailEndpoints{
			ForgotPassword:      true,
			ResetPassword:       true,
			VerifyConfirmPublic: true,
			VerifyRequestAuthed: true,
		},
		MFA: MFAEndpoints{
			Setup:   true,
			Enable:  true,
			Disable: true,
		},
		OAuth: true,
		RBAC: RBACEndpoints{
			ManageRoles:       true,
			ManagePermissions: true,
			AssignRolePerms:   true,
			AssignUserRoles:   true,
			BanUser:           true,
			UnbanUser:         true,
		},
	}
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
	if cfg.RBACAdminPermission == "" {
		cfg.RBACAdminPermission = "rbac.manage"
	}
	if err := seedRBAC(context.Background(), pg, cfg); err != nil {
		return nil, err
	}

	repos := postgres.NewRepositories(pg)
	userRepo := repos.Users
	refreshRepo := repos.RefreshTokens
	rbacRepo := repos.RBAC
	identityRepo := repos.Identities
	mfaRepo := repos.MFA
	auditRepo := repos.Audit
	emailTokenRepo := repos.EmailTokens

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
	emailSvc := service.NewEmailService(userRepo, emailTokenRepo, refreshRepo, sender, cfg.PublicBaseURL, service.EmailHooks{
		BuildVerifyEmailLink:   cfg.Hooks.BuildVerifyEmailLink,
		BuildResetPasswordLink: cfg.Hooks.BuildResetPasswordLink,
		RenderVerifyEmail:      cfg.Hooks.RenderVerifyEmail,
		RenderResetPassword:    cfg.Hooks.RenderResetPassword,
	})
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
		cfg.RequireEmailVerifiedBeforeLogin,
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
	rbacH := handler.NewRBACHandler(rbacSvc, userAdminSvc, auditSvc)
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

// MountCommon attaches common middlewares (request-id, access log, CORS).
// Call this once on the router group you will mount authkit routes into.
func (m *Module) MountCommon(r gin.IRouter) {
	if m.commonMounted {
		return
	}
	r.Use(middleware.RequestID())
	r.Use(middleware.AccessLog())
	r.Use(simpleCORS(m.cfg.CORSAllowedOrigins))
	m.commonMounted = true
}

func (m *Module) MountAuth(r gin.IRouter) {
	memLimiter := middleware.NewInMemoryRateLimiter()
	loginLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:login", m.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:refresh", m.cfg.RateLimitRefreshPerMinute, time.Minute)
	r.POST("/register", m.authH.Register)
	r.POST("/login", loginLimit, m.authH.Login)
	r.POST("/login/2fa", m.authH.CompleteMFA)
	r.POST("/refresh", refreshLimit, m.authH.Refresh)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/logout", m.authH.Logout)
	me.GET("/me", m.authH.Me)
}

func (m *Module) MountEmail(r gin.IRouter) {
	memLimiter := middleware.NewInMemoryRateLimiter()
	forgotLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:forgot", m.cfg.RateLimitForgotPerMinute, time.Minute)
	resetLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:reset_password", m.cfg.RateLimitPasswordResetPerMinute, time.Minute)
	verifyConfirmLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:email_verify_confirm", m.cfg.RateLimitEmailVerifyConfirmPerMinute, time.Minute)
	r.POST("/password/forgot", forgotLimit, m.authH.ForgotPassword)
	r.POST("/password/reset", resetLimit, m.authH.ResetPassword)
	r.POST("/email/verify/confirm", verifyConfirmLimit, m.authH.ConfirmVerifyEmail)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/email/verify/request", m.authH.RequestVerifyEmail)
}

func (m *Module) MountMFA(r gin.IRouter) {
	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/mfa/setup", m.mfaH.Setup)
	me.POST("/mfa/enable", m.mfaH.Enable)
	me.POST("/mfa/disable", m.mfaH.Disable)
}

func (m *Module) MountOAuth(r gin.IRouter) {
	r.GET("/oauth/:provider/login", m.oauthH.Login)
	r.GET("/oauth/:provider/callback", m.oauthH.Callback)
}

func (m *Module) MountRBAC(r gin.IRouter) {
	rbac := r.Group("/")
	rbac.Use(m.authMW)
	rbac.Use(middleware.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission))
	rbac.POST("/roles", m.rbacH.CreateRole)
	rbac.POST("/permissions", m.rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
	rbac.POST("/users/:id/ban", m.rbacH.BanUser)
	rbac.POST("/users/:id/unban", m.rbacH.UnbanUser)
}

// MountAll mounts common middleware and all endpoints.
func (m *Module) MountAll(r gin.IRouter) {
	m.MountCommon(r)
	m.MountAuth(r)
	m.MountEmail(r)
	m.MountMFA(r)
	m.MountOAuth(r)
	m.MountRBAC(r)
}

// MountWithOptions mounts endpoints based on provided options.
func (m *Module) MountWithOptions(r gin.IRouter, opt MountOptions) {
	if opt.Common {
		m.MountCommon(r)
	}

	memLimiter := middleware.NewInMemoryRateLimiter()
	loginLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:login", m.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:refresh", m.cfg.RateLimitRefreshPerMinute, time.Minute)
	forgotLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:forgot", m.cfg.RateLimitForgotPerMinute, time.Minute)
	resetLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:reset_password", m.cfg.RateLimitPasswordResetPerMinute, time.Minute)
	verifyConfirmLimit := middleware.SensitiveRateLimit(m.redis, memLimiter, "rl:email_verify_confirm", m.cfg.RateLimitEmailVerifyConfirmPerMinute, time.Minute)

	// AUTH (public)
	if opt.Auth.Register {
		r.POST("/register", m.authH.Register)
	}
	if opt.Auth.Login {
		r.POST("/login", loginLimit, m.authH.Login)
	}
	if opt.Auth.Login2FA {
		r.POST("/login/2fa", m.authH.CompleteMFA)
	}
	if opt.Auth.Refresh {
		r.POST("/refresh", refreshLimit, m.authH.Refresh)
	}

	// EMAIL (public)
	if opt.Email.ForgotPassword {
		r.POST("/password/forgot", forgotLimit, m.authH.ForgotPassword)
	}
	if opt.Email.ResetPassword {
		r.POST("/password/reset", resetLimit, m.authH.ResetPassword)
	}
	if opt.Email.VerifyConfirmPublic {
		r.POST("/email/verify/confirm", verifyConfirmLimit, m.authH.ConfirmVerifyEmail)
	}

	// OAUTH
	if opt.OAuth {
		r.GET("/oauth/:provider/login", m.oauthH.Login)
		r.GET("/oauth/:provider/callback", m.oauthH.Callback)
	}

	// AUTHED group
	authed := r.Group("/")
	authed.Use(m.authMW)

	if opt.Auth.Logout {
		authed.POST("/logout", m.authH.Logout)
	}
	if opt.Auth.Me {
		authed.GET("/me", m.authH.Me)
	}
	if opt.MFA.Setup {
		authed.POST("/mfa/setup", m.mfaH.Setup)
	}
	if opt.MFA.Enable {
		authed.POST("/mfa/enable", m.mfaH.Enable)
	}
	if opt.MFA.Disable {
		authed.POST("/mfa/disable", m.mfaH.Disable)
	}
	if opt.Email.VerifyRequestAuthed {
		authed.POST("/email/verify/request", m.authH.RequestVerifyEmail)
	}

	// RBAC admin group
	if opt.RBAC.ManageRoles || opt.RBAC.ManagePermissions || opt.RBAC.AssignRolePerms || opt.RBAC.AssignUserRoles || opt.RBAC.BanUser || opt.RBAC.UnbanUser {
		rbac := r.Group("/")
		rbac.Use(m.authMW)
		rbac.Use(middleware.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission))
		if opt.RBAC.ManageRoles {
			rbac.POST("/roles", m.rbacH.CreateRole)
		}
		if opt.RBAC.ManagePermissions {
			rbac.POST("/permissions", m.rbacH.CreatePermission)
		}
		if opt.RBAC.AssignRolePerms {
			rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
		}
		if opt.RBAC.AssignUserRoles {
			rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
		}
		if opt.RBAC.BanUser {
			rbac.POST("/users/:id/ban", m.rbacH.BanUser)
		}
		if opt.RBAC.UnbanUser {
			rbac.POST("/users/:id/unban", m.rbacH.UnbanUser)
		}
	}
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
