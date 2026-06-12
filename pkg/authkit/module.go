package authkit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/admin"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/audit"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/auth"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/cleanup"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/email"
	httpHandlers "github.com/MiraiMagicLab/go-platform-kit/v2/internal/http"
	httpmw "github.com/MiraiMagicLab/go-platform-kit/v2/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/security"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/session"
	storagePostgres "github.com/MiraiMagicLab/go-platform-kit/v2/internal/storage/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/token"
)

// Module is the main auth module that wires all components together.
type Module struct {
	authH         *httpHandlers.AuthHandler
	sessionH      *httpHandlers.SessionHandler
	rbacH         *httpHandlers.RBACHandler
	mfaH          *httpHandlers.MFAHandler
	oauthH        *httpHandlers.OAuthHandler
	authMW        gin.HandlerFunc
	teamTokenMW   gin.HandlerFunc
	rbacSvc       *rbac.RBACService
	emailSvc      *email.EmailService
	cleanup       *cleanup.CleanupService
	redis         *redis.Client
	cfg           Config
	memLimiter    *httpmw.InMemoryRateLimiter
	commonMounted bool
}

// AuthMiddleware returns the JWT auth middleware for protecting host app routes.
func (m *Module) AuthMiddleware() gin.HandlerFunc { return m.authMW }

// TeamTokenMiddleware verifies a control-plane-issued TeamToken (JWKS/RS256).
func (m *Module) TeamTokenMiddleware() gin.HandlerFunc { return m.teamTokenMW }

// RequirePermission returns middleware that checks a dynamic RBAC permission string.
func (m *Module) RequirePermission(permission string) gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, permission, m.cfg.AdminBypassPermission)
}

// RequirePermissionNoBypass returns middleware that checks a permission without admin bypass.
func (m *Module) RequirePermissionNoBypass(permission string) gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, permission, false)
}

// RequireRBACAdmin returns middleware that checks cfg.RBACAdminPermission.
func (m *Module) RequireRBACAdmin() gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission, m.cfg.AdminBypassPermission)
}

// RequestVerifyEmail programmatically requests a verification email for a user.
func (m *Module) RequestVerifyEmail(ctx context.Context, userID uuid.UUID) error {
	if m.emailSvc == nil {
		return errors.New("authkit: email service not configured")
	}
	return m.emailSvc.RequestVerifyEmail(ctx, userID)
}

// ListUserRoles returns current roles for a user.
func (m *Module) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m == nil || m.rbacSvc == nil {
		return nil, errors.New("authkit: rbac service not initialized")
	}
	return m.rbacSvc.ListUserRoles(ctx, userID)
}

// ListUserPermissions returns current permissions for a user.
func (m *Module) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m == nil || m.rbacSvc == nil {
		return nil, errors.New("authkit: rbac service not initialized")
	}
	return m.rbacSvc.ListUserPermissions(ctx, userID)
}

// UserIDFromCtx exposes the authenticated user id from Gin context.
func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) { return httpmw.UserIDFromCtx(c) }

// SessionIDFromCtx exposes the login session id from the access JWT claim.
func SessionIDFromCtx(c *gin.Context) uuid.UUID { return httpmw.SessionIDFromCtx(c) }

// AccessTokenMetaFromCtx exposes access token metadata from Gin context.
func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	return httpmw.AccessTokenMetaFromCtx(c)
}

// New creates a new Module with the given configuration and dependencies.
func New(cfg Config, pg *pgxpool.Pool, redisClient *redis.Client) (*Module, error) {
	if pg == nil {
		return nil, errors.New("pgx pool is required")
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := seedAuthZ(context.Background(), pg, cfg); err != nil {
		return nil, err
	}

	// Create concrete repos
	repos := postgres.NewRepos(pg)

	// Create adapters (ports interfaces)
	userRepo := storagePostgres.NewUserAdapter(repos.User)
	refreshRepo := storagePostgres.NewRefreshTokenAdapter(repos.RefreshToken)
	sessionsRepo := storagePostgres.NewSessionAdapter(repos.Sessions)
	rbacRepo := storagePostgres.NewRBACAdapter(repos.RBAC)
	identityRepo := storagePostgres.NewIdentityAdapter(repos.Identity)
	mfaRepo := storagePostgres.NewMFAAdapter(repos.MFA)
	auditRepo := storagePostgres.NewAuditAdapter(repos.Audit)
	emailTokenRepo := storagePostgres.NewEmailTokenAdapter(repos.EmailToken)

	jwtm := token.NewJWTManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.Issuer)

	var permCache ports.StringSliceCache = ports.NoopStringSliceCache{}
	var denylist ports.AccessTokenDenylist = ports.NoopAccessTokenDenylist{}
	if redisClient != nil {
		permCache = newRedisStringSliceCache(redisClient)
		denylist = newRedisAccessTokenDenylist(redisClient)
	}

	var mfaCipher mfa.Cipher
	if cfg.DataEncryptionKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.DataEncryptionKeyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid DataEncryptionKeyB64: %w", err)
		}
		c, err := security.NewStringCipher(key)
		if err != nil {
			return nil, err
		}
		mfaCipher = c
	}

	rbacSvc := rbac.NewRBACService(rbacRepo, permCache, cfg.PermissionsCacheTTL)
	userAdminSvc := admin.NewUserAdminService(userRepo, refreshRepo)
	mfaSvc := mfa.NewMFAService(mfaRepo, cfg.Issuer, mfaCipher)
	auditSvc := audit.NewAuditService(auditRepo)
	cleanupSvc := cleanup.NewCleanupService(refreshRepo, mfaRepo, emailTokenRepo)

	var sender ports.EmailSender
	if cfg.SMTPHost != "" && cfg.SMTPUser != "" && cfg.SMTPPass != "" && cfg.SMTPFrom != "" {
		sender = newSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)
	}
	emailSvc := email.NewEmailService(userRepo, emailTokenRepo, refreshRepo, sender, cfg.PublicBaseURL, cfg.ResetPasswordDelivery, email.Hooks{
		BuildVerifyEmailLink:   cfg.Hooks.BuildVerifyEmailLink,
		BuildResetPasswordLink: cfg.Hooks.BuildResetPasswordLink,
		RenderVerifyEmail:      cfg.Hooks.RenderVerifyEmail,
		RenderResetPassword:    cfg.Hooks.RenderResetPassword,
	})

	authCfg := auth.Config{
		AccessTokenTTL:         cfg.AccessTokenTTL,
		RefreshTokenTTL:        cfg.RefreshTokenTTL,
		Issuer:                 cfg.Issuer,
		RequireEmailVerified:   cfg.RequireEmailVerifiedBeforeLogin,
		MaxFailedLoginAttempts: cfg.MaxFailedLoginAttempts,
		AccountLockDuration:    cfg.AccountLockDuration,
	}
	authSvc := auth.NewAuthService(userRepo, refreshRepo, mfaRepo, mfaSvc, denylist, jwtm, authCfg)

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
	oauthSvc := oauth.NewOAuthService(identityRepo, userRepo, googleCfg, facebookCfg)

	esvc := emailSvc
	sessionHook := cfg.Hooks.AfterSessionIssued
	authLC := &httpHandlers.Lifecycle{
		AfterSessionIssued: func(ctx *gin.Context, reason string, userID string, emailAddr *string, ip, ua string) {
			if sessionHook != nil {
				uid, _ := uuid.Parse(userID)
				sessionHook(ctx.Request.Context(), SessionIssuedReason(reason), uid, emailAddr, ip, ua)
			}
			if reason == "register" && sessionHook == nil && esvc != nil {
				uid, _ := uuid.Parse(userID)
				_ = esvc.RequestVerifyEmail(ctx.Request.Context(), uid)
			}
		},
	}

	var emailValidate httpHandlers.EmailValidator
	if cfg.EmailValidator != nil {
		emailValidate = httpHandlers.EmailValidator(cfg.EmailValidator)
	}
	authH := httpHandlers.NewAuthHandler(authSvc, emailSvc, rbacSvc, userRepo, auditSvc, authLC, emailValidate)
	sessionSvc := session.NewSessionService(sessionsRepo, refreshRepo, denylist)
	sessionH := httpHandlers.NewSessionHandler(sessionSvc, auditSvc)
	rbacH := httpHandlers.NewRBACHandler(rbacSvc, userAdminSvc, auditSvc)
	mfaH := httpHandlers.NewMFAHandler(mfaSvc, auditSvc, userRepo)
	oauthH := httpHandlers.NewOAuthHandler(oauthSvc, authSvc, "/auth", cfg.FrontendBaseURL, cfg.OAuthCookieSecure, authLC)

	authMW := httpmw.JWTAuth(jwtm, userRepo, denylist)

	var teamTokenMW gin.HandlerFunc
	if cfg.ControlPlaneJWKSURL != "" && cfg.ControlPlaneAudience != "" {
		v, err := httpmw.NewTeamTokenVerifier(cfg.ControlPlaneJWKSURL, cfg.ControlPlaneIssuer, cfg.ControlPlaneAudience)
		if err != nil {
			return nil, err
		}
		teamTokenMW = v.Middleware()
	}

	return &Module{
		authH:       authH,
		sessionH:    sessionH,
		rbacH:       rbacH,
		mfaH:        mfaH,
		oauthH:      oauthH,
		authMW:      authMW,
		teamTokenMW: teamTokenMW,
		rbacSvc:     rbacSvc,
		emailSvc:    emailSvc,
		cleanup:     cleanupSvc,
		redis:       redisClient,
		cfg:         cfg,
		memLimiter:  httpmw.NewInMemoryRateLimiter(),
	}, nil
}

// StartBackgroundCleanup launches a goroutine to periodically purge expired tokens.
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

// seedAuthZ seeds roles and permissions based on config.
func seedAuthZ(ctx context.Context, pg *pgxpool.Pool, cfg Config) error {
	for _, role := range cfg.SeedRoles {
		if role == "" {
			continue
		}
		if _, err := pg.Exec(ctx, `INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, role); err != nil {
			return fmt.Errorf("seed role %q: %w", role, err)
		}
	}
	if !cfg.AuthZ.usesRBAC() {
		return nil
	}
	for _, perm := range cfg.SeedPermissions {
		if perm == "" {
			continue
		}
		if _, err := pg.Exec(ctx, `INSERT INTO permissions (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, perm); err != nil {
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
				INSERT INTO role_permissions (role_id, permission_id)
				SELECT r.id, p.id
				FROM roles r
				JOIN permissions p ON p.name = $2
				WHERE r.name = $1
				ON CONFLICT DO NOTHING
			`, role, perm); err != nil {
				return fmt.Errorf("seed role_permission %q->%q: %w", role, perm, err)
			}
		}
	}
	return nil
}

// Redis adapter types (minimal wrappers to avoid direct go-redis dependency in this package).
type redisClientAdapter struct {
	rdb *redis.Client
}

func newRedisStringSliceCache(rdb *redis.Client) ports.StringSliceCache {
	return &redisStringSliceCacheAdapter{rdb: rdb}
}

type redisStringSliceCacheAdapter struct {
	rdb *redis.Client
}

func (c *redisStringSliceCacheAdapter) Get(ctx context.Context, key string) ([]string, bool, error) {
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		return nil, false, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(val), &out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (c *redisStringSliceCacheAdapter) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, string(b), ttl).Err()
}

func (c *redisStringSliceCacheAdapter) Del(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, key).Err()
}

func newRedisAccessTokenDenylist(rdb *redis.Client) ports.AccessTokenDenylist {
	return &redisDenylistAdapter{rdb: rdb}
}

type redisDenylistAdapter struct {
	rdb *redis.Client
}

func (d *redisDenylistAdapter) IsDenied(ctx context.Context, jti string) (bool, error) {
	_, err := d.rdb.Get(ctx, "deny:access:"+jti).Result()
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (d *redisDenylistAdapter) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	return d.rdb.Set(ctx, "deny:access:"+jti, "1", ttl).Err()
}

// SMTP sender adapter.
type smtpSenderAdapter struct {
	host, user, pass, from string
	port                   int
}

func newSMTPSender(host string, port int, user, pass, from string) ports.EmailSender {
	return &smtpSenderAdapter{host: host, port: port, user: user, pass: pass, from: from}
}

func (s *smtpSenderAdapter) Send(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.from, to, subject, body)
	return sendMail(addr, s.user, s.pass, s.from, []string{to}, []byte(msg))
}

// sendMail is a wrapper around net/smtp.SendMail.
func sendMail(addr, username, password, from string, to []string, msg []byte) error {
	auth := smtp.PlainAuth("", username, password, addr)
	return smtp.SendMail(addr, auth, from, to, msg)
}
