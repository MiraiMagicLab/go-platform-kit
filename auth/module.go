package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/crypto"
	ginhandlers "github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin"
	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/postgres"
	redisstore "github.com/MiraiMagicLab/go-platform-kit/auth/internal/redis"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/admin"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/audit"
	authsvc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/auth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/cleanup"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/email"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/session"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/smtp"
)

// Module wires auth HTTP handlers, services, and middleware for embedding in a Gin app.
type Module struct {
	authH         *ginhandlers.AuthHandler
	sessionH      *ginhandlers.SessionHandler
	rbacH         *ginhandlers.RBACHandler
	mfaH          *ginhandlers.MFAHandler
	oauthH        *ginhandlers.OAuthHandler
	authMW        gin.HandlerFunc
	teamTokenMW   gin.HandlerFunc
	rbacSvc       *rbac.RBACService
	emailSvc      *email.EmailService
	cleanup       *cleanup.CleanupService
	redis         *goredis.Client
	cfg           Config
	memLimiter    *httpmw.InMemoryRateLimiter
	commonMounted bool
}

// AuthMiddleware validates JWT access tokens for host application routes.
func (m *Module) AuthMiddleware() gin.HandlerFunc { return m.authMW }

func (m *Module) TeamTokenMiddleware() gin.HandlerFunc { return m.teamTokenMW }

func (m *Module) RequirePermission(permission string) gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, permission, m.cfg.AdminBypassPermission)
}

func (m *Module) RequirePermissionNoBypass(permission string) gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, permission, false)
}

func (m *Module) RequireRBACAdmin() gin.HandlerFunc {
	return httpmw.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission, m.cfg.AdminBypassPermission)
}

func (m *Module) RequestVerifyEmail(ctx context.Context, userID uuid.UUID) error {
	if m.emailSvc == nil {
		return errors.New("auth: email service not configured")
	}
	return m.emailSvc.RequestVerifyEmail(ctx, userID)
}

func (m *Module) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m == nil || m.rbacSvc == nil {
		return nil, errors.New("auth: rbac service not initialized")
	}
	return m.rbacSvc.ListUserRoles(ctx, userID)
}

func (m *Module) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m == nil || m.rbacSvc == nil {
		return nil, errors.New("auth: rbac service not initialized")
	}
	return m.rbacSvc.ListUserPermissions(ctx, userID)
}

func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) { return httpmw.UserIDFromCtx(c) }

func SessionIDFromCtx(c *gin.Context) uuid.UUID { return httpmw.SessionIDFromCtx(c) }

func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	return httpmw.AccessTokenMetaFromCtx(c)
}

// New creates a Module from functional options.
func New(ctx context.Context, opts ...Option) (*Module, error) {
	o := &options{cfg: DefaultConfig()}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	if o.pg == nil {
		return nil, errors.New("auth: postgres pool is required (WithPostgres)")
	}
	o.cfg.ApplyDefaults()
	if err := o.cfg.Validate(); err != nil {
		return nil, err
	}
	if err := seedAuthZ(ctx, o.pg, o.cfg); err != nil {
		return nil, err
	}

	store := o.store
	if store == nil {
		repos := postgres.NewRepos(o.pg)
		s := Store{
			Users:        postgres.NewUserAdapter(repos.User),
			RefreshToken: postgres.NewRefreshTokenAdapter(repos.RefreshToken),
			Sessions:     postgres.NewSessionAdapter(repos.Sessions),
			RBAC:         postgres.NewRBACAdapter(repos.RBAC),
			Identity:     postgres.NewIdentityAdapter(repos.Identity),
			MFA:          postgres.NewMFAAdapter(repos.MFA),
			Audit:        postgres.NewAuditAdapter(repos.Audit),
			EmailToken:   postgres.NewEmailTokenAdapter(repos.EmailToken),
		}
		store = &s
	}

	jwtm := o.jwt
	if jwtm == nil {
		jwtm = NewJWTManager(o.cfg.JWTAccessSecret, o.cfg.JWTRefreshSecret, o.cfg.Issuer)
	}

	permCache := o.permCache
	denylist := o.denylist
	if permCache == nil {
		permCache = NoopStringSliceCache{}
	}
	if denylist == nil {
		denylist = NoopAccessTokenDenylist{}
	}
	if o.redis != nil {
		if _, noop := permCache.(NoopStringSliceCache); noop || o.permCache == nil {
			if c := redisstore.NewStringSliceCache(o.redis); c != nil {
				permCache = c
			}
		}
		if _, noop := denylist.(NoopAccessTokenDenylist); noop || o.denylist == nil {
			if d := redisstore.NewAccessTokenDenylist(o.redis); d != nil {
				denylist = d
			}
		}
	}

	var mfaCipher mfa.Cipher
	if o.cfg.DataEncryptionKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(o.cfg.DataEncryptionKeyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid DataEncryptionKeyB64: %w", err)
		}
		c, err := crypto.NewStringCipher(key)
		if err != nil {
			return nil, err
		}
		mfaCipher = c
	}

	rbacSvc := rbac.NewRBACService(store.RBAC, permCache, o.cfg.PermissionsCacheTTL)
	userAdminSvc := admin.NewUserAdminService(store.Users, store.RefreshToken)
	mfaSvc := mfa.NewMFAService(store.MFA, o.cfg.Issuer, mfaCipher)
	auditSvc := audit.NewAuditService(store.Audit)
	cleanupSvc := cleanup.NewCleanupService(store.RefreshToken, store.MFA, store.EmailToken)

	sender := o.emailSender
	if sender == nil && o.cfg.SMTPHost != "" && o.cfg.SMTPUser != "" && o.cfg.SMTPPass != "" && o.cfg.SMTPFrom != "" {
		sender = smtp.NewSender(o.cfg.SMTPHost, o.cfg.SMTPPort, o.cfg.SMTPUser, o.cfg.SMTPPass, o.cfg.SMTPFrom)
	}
	emailSvc := email.NewEmailService(store.Users, store.EmailToken, store.RefreshToken, sender, o.cfg.PublicBaseURL, o.cfg.ResetPasswordDelivery, email.Hooks{
		BuildVerifyEmailLink:   o.cfg.Hooks.BuildVerifyEmailLink,
		BuildResetPasswordLink: o.cfg.Hooks.BuildResetPasswordLink,
		RenderVerifyEmail:      o.cfg.Hooks.RenderVerifyEmail,
		RenderResetPassword:    o.cfg.Hooks.RenderResetPassword,
	})

	authCfg := authsvc.Config{
		AccessTokenTTL:         o.cfg.AccessTokenTTL,
		RefreshTokenTTL:        o.cfg.RefreshTokenTTL,
		Issuer:                 o.cfg.Issuer,
		RequireEmailVerified:   o.cfg.RequireEmailVerifiedBeforeLogin,
		MaxFailedLoginAttempts: o.cfg.MaxFailedLoginAttempts,
		AccountLockDuration:    o.cfg.AccountLockDuration,
	}
	authService := authsvc.NewAuthService(store.Users, store.RefreshToken, store.MFA, mfaSvc, denylist, jwtm, authCfg)

	var googleCfg *oauth2.Config
	if o.cfg.GoogleClientID != "" && o.cfg.GoogleClientSecret != "" && o.cfg.GoogleRedirectURL != "" {
		googleCfg = &oauth2.Config{
			ClientID:     o.cfg.GoogleClientID,
			ClientSecret: o.cfg.GoogleClientSecret,
			RedirectURL:  o.cfg.GoogleRedirectURL,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email"},
		}
	}
	var facebookCfg *oauth2.Config
	if o.cfg.FacebookClientID != "" && o.cfg.FacebookClientSecret != "" && o.cfg.FacebookRedirectURL != "" {
		facebookCfg = &oauth2.Config{
			ClientID:     o.cfg.FacebookClientID,
			ClientSecret: o.cfg.FacebookClientSecret,
			RedirectURL:  o.cfg.FacebookRedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://www.facebook.com/v21.0/dialog/oauth",
				TokenURL: "https://graph.facebook.com/v21.0/oauth/access_token",
			},
			Scopes: []string{"email"},
		}
	}
	oauthService := oauth.NewOAuthService(store.Identity, store.Users, googleCfg, facebookCfg)

	esvc := emailSvc
	sessionHook := o.cfg.Hooks.AfterSessionIssued
	authLC := &ginhandlers.Lifecycle{
		AfterSessionIssued: func(c *gin.Context, reason string, userID string, emailAddr *string, ip, ua string) {
			if sessionHook != nil {
				uid, _ := uuid.Parse(userID)
				sessionHook(c.Request.Context(), SessionIssuedReason(reason), uid, emailAddr, ip, ua)
			}
			if reason == "register" && sessionHook == nil && esvc != nil {
				uid, _ := uuid.Parse(userID)
				_ = esvc.RequestVerifyEmail(c.Request.Context(), uid)
			}
		},
	}

	var emailValidate ginhandlers.EmailValidator
	if o.cfg.EmailValidator != nil {
		emailValidate = ginhandlers.EmailValidator(o.cfg.EmailValidator)
	}
	authH := ginhandlers.NewAuthHandler(authService, emailSvc, rbacSvc, store.Users, auditSvc, authLC, emailValidate)
	sessionSvc := session.NewSessionService(store.Sessions, store.RefreshToken, denylist)
	sessionH := ginhandlers.NewSessionHandler(sessionSvc, auditSvc)
	rbacH := ginhandlers.NewRBACHandler(rbacSvc, userAdminSvc, auditSvc)
	mfaH := ginhandlers.NewMFAHandler(mfaSvc, auditSvc, store.Users)
	oauthH := ginhandlers.NewOAuthHandler(oauthService, authService, "/auth", o.cfg.FrontendBaseURL, o.cfg.OAuthCookieSecure, authLC)

	authMW := httpmw.JWTAuth(jwtm, store.Users, denylist)

	var teamTokenMW gin.HandlerFunc
	if o.cfg.ControlPlaneJWKSURL != "" && o.cfg.ControlPlaneAudience != "" {
		v, err := httpmw.NewTeamTokenVerifier(o.cfg.ControlPlaneJWKSURL, o.cfg.ControlPlaneIssuer, o.cfg.ControlPlaneAudience)
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
		redis:       o.redis,
		cfg:         o.cfg,
		memLimiter:  httpmw.NewInMemoryRateLimiter(),
	}, nil
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
