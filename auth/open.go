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

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/handler"
	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/postgres"
	redisstore "github.com/MiraiMagicLab/go-platform-kit/auth/internal/redis"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/admin"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/audit"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/cleanup"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/email"
	login "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/login"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/session"
	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
)

// Auth is the headless auth runtime. Open it once, then call use-case methods from host HTTP handlers.
type Auth struct {
	loginSvc    *login.AuthService
	sessionSvc  *session.SessionService
	emailSvc    *email.EmailService
	rbacSvc     *rbac.RBACService
	adminSvc    *admin.UserAdminService
	mfaSvc      *mfa.MFAService
	oauthSvc    *oauth.OAuthService
	auditSvc    *audit.AuditService
	cleanup     *cleanup.CleanupService
	users       ports.UserRepository
	authMW      gin.HandlerFunc
	teamTokenMW gin.HandlerFunc
	cfg          Config
	redis        *goredis.Client
	rateLimiter  httpmw.RedisRateLimiter
	memLimiter   *httpmw.InMemoryRateLimiter

	authH         *handler.AuthHandler
	sessionH      *handler.SessionHandler
	rbacH         *handler.RBACHandler
	mfaH          *handler.MFAHandler
	oauthH        *handler.OAuthHandler
	commonMounted bool
}

// Open wires auth from functional options.
func Open(ctx context.Context, opts ...Option) (*Auth, error) {
	return newAuth(ctx, opts...)
}

// New is an alias for [Open].
func New(ctx context.Context, opts ...Option) (*Auth, error) {
	return Open(ctx, opts...)
}

func newAuth(ctx context.Context, opts ...Option) (*Auth, error) {
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

	logger := o.logger
	if logger == nil {
		logger = log.Noop{}
	}
	httpmw.SetLogger(logger)

	store := o.store
	if store == nil {
		s := postgres.NewStore(o.pg)
		store = &s
	}

	jwtm := o.jwt
	if jwtm == nil {
		jwtm = jwt.NewManager(o.cfg.JWTAccessSecret, o.cfg.JWTRefreshSecret, o.cfg.Issuer)
	}

	permCache := o.permCache
	denylist := o.denylist
	if permCache == nil {
		permCache = ports.NoopStringSliceCache{}
	}
	if denylist == nil {
		denylist = ports.NoopAccessTokenDenylist{}
	}
	if o.redis != nil {
		if _, noop := permCache.(ports.NoopStringSliceCache); noop || o.permCache == nil {
			if c := redisstore.NewStringSliceCache(o.redis); c != nil {
				permCache = c
			}
		}
		if _, noop := denylist.(ports.NoopAccessTokenDenylist); noop || o.denylist == nil {
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
		c, err := security.NewStringCipher(key)
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
		var err error
		sender, err = mail.Open(mail.Config{
			Host: o.cfg.SMTPHost,
			Port: o.cfg.SMTPPort,
			User: o.cfg.SMTPUser,
			Pass: o.cfg.SMTPPass,
			From: o.cfg.SMTPFrom,
		})
		if err != nil {
			return nil, err
		}
	}
	emailSvc := email.NewEmailService(store.Users, store.EmailToken, store.RefreshToken, sender, o.cfg.PublicBaseURL, o.cfg.ResetPasswordDelivery, email.Hooks{
		BuildVerifyEmailLink:   o.cfg.Hooks.BuildVerifyEmailLink,
		BuildResetPasswordLink: o.cfg.Hooks.BuildResetPasswordLink,
		RenderVerifyEmail:      o.cfg.Hooks.RenderVerifyEmail,
		RenderResetPassword:    o.cfg.Hooks.RenderResetPassword,
	})

	authCfg := login.Config{
		AccessTokenTTL:         o.cfg.AccessTokenTTL,
		RefreshTokenTTL:        o.cfg.RefreshTokenTTL,
		Issuer:                 o.cfg.Issuer,
		RequireEmailVerified:   o.cfg.RequireEmailVerifiedBeforeLogin,
		MaxFailedLoginAttempts: o.cfg.MaxFailedLoginAttempts,
		AccountLockDuration:    o.cfg.AccountLockDuration,
	}
	authService := login.NewAuthService(store.Users, store.Sessions, store.RefreshToken, store.MFA, mfaSvc, denylist, jwtm, authCfg)

	var googleCfg = oauth.NewGoogleOAuthConfig(o.cfg.GoogleClientID, o.cfg.GoogleClientSecret, o.cfg.GoogleRedirectURL)
	if !o.cfg.GoogleOAuthConfigured() {
		googleCfg = nil
	} else if o.oauthTokenURL != "" && googleCfg != nil {
		googleCfg.Endpoint.TokenURL = o.oauthTokenURL
	}
	oauthService := oauth.NewOAuthService(store.Identity, store.Users, googleCfg, o.oauthOpts...)

	esvc := emailSvc
	sessionHook := o.cfg.Hooks.AfterSessionIssued
	authLC := &handler.Lifecycle{
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

	var emailValidate handler.EmailValidator
	if o.cfg.EmailValidator != nil {
		emailValidate = handler.EmailValidator(o.cfg.EmailValidator)
	}
	authH := handler.NewAuthHandler(authService, emailSvc, rbacSvc, store.Users, auditSvc, o.cfg.DefaultRegisterRole, authLC, emailValidate)
	sessionSvc := session.NewSessionService(store.Sessions, store.RefreshToken, denylist)
	sessionH := handler.NewSessionHandler(sessionSvc, auditSvc)
	rbacH := handler.NewRBACHandler(rbacSvc, userAdminSvc, auditSvc)
	mfaH := handler.NewMFAHandler(mfaSvc, auditSvc, store.Users)
	oauthH := handler.NewOAuthHandler(oauthService, authService, rbacSvc, o.cfg.DefaultRegisterRole, "/auth", o.cfg.FrontendBaseURL, o.cfg.OAuthCookieSecure, authLC)

	var userCache httpmw.UserAuthCache
	if o.redis != nil {
		userCache = redisstore.NewUserAuthCache(o.redis, o.cfg.JWTUserCacheTTL)
	}
	authMW := httpmw.JWTAuth(jwtm, store.Users, denylist, userCache)

	var rateLimiter httpmw.RedisRateLimiter
	if o.redis != nil {
		rateLimiter = redisstore.NewRateLimiter(o.redis)
	}

	var teamTokenMW gin.HandlerFunc
	if o.cfg.ControlPlaneJWKSURL != "" && o.cfg.ControlPlaneAudience != "" {
		v, err := httpmw.NewTeamTokenVerifier(o.cfg.ControlPlaneJWKSURL, o.cfg.ControlPlaneIssuer, o.cfg.ControlPlaneAudience)
		if err != nil {
			return nil, err
		}
		teamTokenMW = v.Middleware()
	}

	return &Auth{
		loginSvc:    authService,
		sessionSvc:  sessionSvc,
		emailSvc:    emailSvc,
		rbacSvc:     rbacSvc,
		adminSvc:    userAdminSvc,
		mfaSvc:      mfaSvc,
		oauthSvc:    oauthService,
		auditSvc:    auditSvc,
		cleanup:     cleanupSvc,
		users:       store.Users,
		authMW:      authMW,
		teamTokenMW: teamTokenMW,
		cfg:         o.cfg,
		redis:       o.redis,
		rateLimiter: rateLimiter,
		memLimiter:  httpmw.NewInMemoryRateLimiter(),
		authH:       authH,
		sessionH:    sessionH,
		rbacH:       rbacH,
		mfaH:        mfaH,
		oauthH:      oauthH,
	}, nil
}

// StartCleanup runs expired token/session cleanup on a background ticker.
func (a *Auth) StartCleanup(ctx context.Context, interval time.Duration) {
	if a == nil || a.cleanup == nil {
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
				a.cleanup.RunOnce(ctx)
			}
		}
	}()
}

// StartBackgroundCleanup is an alias for [Auth.StartCleanup].
func (a *Auth) StartBackgroundCleanup(ctx context.Context, interval time.Duration) {
	a.StartCleanup(ctx, interval)
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
