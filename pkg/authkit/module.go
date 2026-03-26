package authkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/tienh/authsvc/internal/handler"
	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/repository/postgres"
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

	// Dynamic RBAC bootstrap from host project.
	SeedRoles           []string
	SeedPermissions     []string
	SeedRolePermissions map[string][]string // role -> []permission names
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
	}
}

type Module struct {
	authH  *handler.AuthHandler
	rbacH  *handler.RBACHandler
	mfaH   *handler.MFAHandler
	oauthH *handler.OAuthHandler

	authMW  gin.HandlerFunc
	rbacSvc *service.RBACService
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

	jwtm := token.NewJWTManager(cfg.JWTAccessSecret, cfg.JWTRefreshSecret, cfg.Issuer)

	var permCache service.StringSliceCache = service.NoopStringSliceCache{}
	var denylist service.AccessTokenDenylist = service.NoopAccessTokenDenylist{}
	if redisClient != nil {
		permCache = service.NewRedisStringSliceCache(redisClient)
		denylist = service.NewRedisAccessTokenDenylist(redisClient)
	}

	rbacSvc := service.NewRBACService(rbacRepo, permCache, cfg.PermissionsCacheTTL)
	mfaSvc := service.NewMFAService(mfaRepo, cfg.Issuer)
	authSvc := service.NewAuthService(
		userRepo,
		refreshRepo,
		mfaRepo,
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

	authH := handler.NewAuthHandler(authSvc, rbacSvc, userRepo)
	rbacH := handler.NewRBACHandler(rbacSvc)
	mfaH := handler.NewMFAHandler(mfaSvc)
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
	}, nil
}

// Mount registers auth/rbac/mfa/oauth routes into an existing Gin router/group.
func (m *Module) Mount(r gin.IRouter) {
	r.POST("/register", m.authH.Register)
	r.POST("/login", m.authH.Login)
	r.POST("/login/2fa", m.authH.CompleteMFA)
	r.POST("/refresh", m.authH.Refresh)
	r.GET("/oauth/:provider/login", m.oauthH.Login)
	r.GET("/oauth/:provider/callback", m.oauthH.Callback)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/logout", m.authH.Logout)
	me.GET("/me", m.authH.Me)
	me.POST("/mfa/setup", m.mfaH.Setup)
	me.POST("/mfa/enable", m.mfaH.Enable)
	me.POST("/mfa/disable", m.mfaH.Disable)

	rbac := r.Group("/")
	rbac.Use(m.authMW)
	rbac.Use(middleware.RequirePermission(m.rbacSvc, "rbac.manage"))
	rbac.POST("/roles", m.rbacH.CreateRole)
	rbac.POST("/permissions", m.rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
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
