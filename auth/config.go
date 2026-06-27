package auth

import (
	"errors"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/util"
)

// Config holds all configuration for the auth module.
type Config struct {
	JWTAccessSecret     string
	JWTRefreshSecret    string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	PermissionsCacheTTL time.Duration
	Issuer              string

	ControlPlaneJWKSURL  string
	ControlPlaneIssuer   string
	ControlPlaneAudience string

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	FacebookClientID     string
	FacebookClientSecret string
	FacebookRedirectURL  string

	PublicBaseURL   string
	FrontendBaseURL string

	DataEncryptionKeyB64 string

	SeedRoles           []string
	SeedPermissions     []string
	SeedRolePermissions map[string][]string

	RBACAdminPermission string

	RequireEmailVerifiedBeforeLogin bool

	RateLimitLoginPerMinute              int
	RateLimitRefreshPerMinute            int
	RateLimitForgotPerMinute             int
	RateLimitPasswordResetPerMinute      int
	RateLimitEmailVerifyConfirmPerMinute int
	CORSAllowedOrigins                   []string

	SMTPHost              string
	SMTPPort              int
	SMTPUser              string
	SMTPPass              string
	SMTPFrom              string
	ResetPasswordDelivery string

	Hooks Hooks

	AuthZ AuthZConfig

	MaxFailedLoginAttempts int
	AccountLockDuration    time.Duration

	AdminBypassPermission bool

	RequirePasswordForMFADisable bool

	OAuthCookieSecure bool

	EmailValidator util.EmailValidator
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     720 * time.Hour,
		PermissionsCacheTTL: 30 * time.Second,
		Issuer:              "authkit",
		ControlPlaneIssuer:  "control-plane",
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
		ResetPasswordDelivery:                "otp",
		AuthZ:                                AuthZConfig{Mode: AuthZRbac},
		MaxFailedLoginAttempts:               5,
		AccountLockDuration:                  15 * time.Minute,
		AdminBypassPermission:                true,
		RequirePasswordForMFADisable:         true,
		OAuthCookieSecure:                    false,
	}
}

// Validate checks the configuration for required fields.
func (c Config) Validate() error {
	if c.JWTAccessSecret == "" || c.JWTRefreshSecret == "" {
		return errors.New("JWT access/refresh secrets are required")
	}
	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return errors.New("token TTL must be > 0")
	}
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	if c.RBACAdminPermission == "" {
		return errors.New("RBACAdminPermission is required")
	}
	return c.AuthZ.validate()
}

// ApplyDefaults fills in zero-value fields with defaults.
func (c *Config) ApplyDefaults() {
	if c.Issuer == "" {
		c.Issuer = "authkit"
	}
	if c.RBACAdminPermission == "" {
		c.RBACAdminPermission = "rbac.manage"
	}
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = 15 * time.Minute
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = 720 * time.Hour
	}
	if c.PermissionsCacheTTL <= 0 {
		c.PermissionsCacheTTL = 30 * time.Second
	}
	if c.MaxFailedLoginAttempts <= 0 {
		c.MaxFailedLoginAttempts = 5
	}
	if c.AccountLockDuration <= 0 {
		c.AccountLockDuration = 15 * time.Minute
	}
	if c.SMTPPort <= 0 {
		c.SMTPPort = 587
	}
	if len(c.SeedRoles) == 0 {
		c.SeedRoles = []string{"admin", "user"}
	}
	if len(c.SeedPermissions) == 0 {
		c.SeedPermissions = []string{"rbac.manage"}
	}
	if len(c.SeedRolePermissions) == 0 {
		c.SeedRolePermissions = map[string][]string{"admin": {"rbac.manage"}}
	}
	if len(c.CORSAllowedOrigins) == 0 {
		c.CORSAllowedOrigins = []string{"*"}
	}
	if c.ControlPlaneIssuer == "" {
		c.ControlPlaneIssuer = "control-plane"
	}
}
