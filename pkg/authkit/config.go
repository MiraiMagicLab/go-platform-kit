package authkit

import (
	"errors"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/utils"
)

// Config holds all configuration for the auth module.
type Config struct {
	// JWTAccessSecret is the HMAC-SHA256 signing key for access tokens.
	JWTAccessSecret string
	// JWTRefreshSecret is the HMAC-SHA256 signing key for refresh tokens.
	JWTRefreshSecret string
	// AccessTokenTTL controls the access token expiration duration. Default: 15m.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL controls the refresh token expiration duration. Default: 720h (30 days).
	RefreshTokenTTL time.Duration
	// PermissionsCacheTTL controls how long user permissions are cached in Redis. Default: 30s.
	PermissionsCacheTTL time.Duration
	// Issuer is the JWT "iss" claim value. Default: "authkit".
	Issuer string

	// ControlPlaneJWKSURL is the JWKS endpoint URL for verifying control-plane TeamTokens.
	ControlPlaneJWKSURL string
	// ControlPlaneIssuer is the expected "iss" claim value for control-plane tokens. Default: "control-plane".
	ControlPlaneIssuer string
	// ControlPlaneAudience is the expected "aud" claim value for control-plane tokens.
	ControlPlaneAudience string

	// GoogleClientID is the Google OAuth2 client ID for social login.
	GoogleClientID string
	// GoogleClientSecret is the Google OAuth2 client secret.
	GoogleClientSecret string
	// GoogleRedirectURL is the OAuth2 callback URL for Google login.
	GoogleRedirectURL string

	// FacebookClientID is the Facebook OAuth2 client ID for social login.
	FacebookClientID string
	// FacebookClientSecret is the Facebook OAuth2 client secret.
	FacebookClientSecret string
	// FacebookRedirectURL is the OAuth2 callback URL for Facebook login.
	FacebookRedirectURL string

	// PublicBaseURL is the publicly accessible base URL of the auth service. Default: "http://localhost:8080".
	PublicBaseURL string
	// FrontendBaseURL is the frontend application base URL used for OAuth redirects.
	FrontendBaseURL string

	// DataEncryptionKeyB64 is a 32-byte key encoded in base64 for encrypting sensitive data (e.g. TOTP secret).
	DataEncryptionKeyB64 string

	// SeedRoles lists role names to bootstrap on first startup. Default: ["admin", "user"].
	SeedRoles []string
	// SeedPermissions lists permission names to bootstrap on first startup. Default: ["rbac.manage"].
	SeedPermissions []string
	// SeedRolePermissions maps role names to their initial permission sets. Default: admin -> ["rbac.manage"].
	SeedRolePermissions map[string][]string

	// RBACAdminPermission is the permission name required to access RBAC admin endpoints. Default: "rbac.manage".
	RBACAdminPermission string

	// RequireEmailVerifiedBeforeLogin prevents issuing tokens until the user's email is verified.
	RequireEmailVerifiedBeforeLogin bool

	// RateLimitLoginPerMinute is the max login attempts per IP per minute. Default: 20.
	RateLimitLoginPerMinute int
	// RateLimitRefreshPerMinute is the max refresh requests per IP per minute. Default: 60.
	RateLimitRefreshPerMinute int
	// RateLimitForgotPerMinute is the max forgot-password requests per IP per minute. Default: 10.
	RateLimitForgotPerMinute int
	// RateLimitPasswordResetPerMinute is the max password-reset requests per IP per minute. Default: 10.
	RateLimitPasswordResetPerMinute int
	// RateLimitEmailVerifyConfirmPerMinute is the max email verification requests per IP per minute. Default: 10.
	RateLimitEmailVerifyConfirmPerMinute int
	// CORSAllowedOrigins lists allowed CORS origins. Default: ["*"].
	CORSAllowedOrigins []string

	// SMTPHost is the SMTP server hostname for sending emails.
	SMTPHost string
	// SMTPPort is the SMTP server port. Default: 587.
	SMTPPort int
	// SMTPUser is the SMTP authentication username.
	SMTPUser string
	// SMTPPass is the SMTP authentication password.
	SMTPPass string
	// SMTPFrom is the "From" address for outbound emails.
	SMTPFrom string
	// ResetPasswordDelivery configures forgot-password email type: "otp" (default) or "link".
	ResetPasswordDelivery string

	// Hooks contains customization callbacks for email templates and post-session side effects.
	Hooks Hooks

	// AuthZ configures the authorization mode (none, role, rbac).
	AuthZ AuthZConfig

	// MaxFailedLoginAttempts is the number of consecutive failed logins before account lock. Default: 5.
	MaxFailedLoginAttempts int
	// AccountLockDuration is how long an account stays locked after exceeding failed login attempts. Default: 15m.
	AccountLockDuration time.Duration

	// AdminBypassPermission allows admin users to bypass certain restrictions. Default: true.
	AdminBypassPermission bool

	// RequirePasswordForMFADisable requires the user's password to disable MFA. Default: true.
	RequirePasswordForMFADisable bool

	// OAuthCookieSecure sets the Secure flag on OAuth CSRF state cookies. Set true in production with HTTPS.
	OAuthCookieSecure bool

	// EmailValidator is a custom email format validator. Nil uses utils.DefaultEmailValidator.
	EmailValidator utils.EmailValidator
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

// Validate checks the configuration for required fields and returns an error if invalid.
func (c Config) Validate() error {
	if c.JWTAccessSecret == "" || c.JWTRefreshSecret == "" {
		return errors.New("JWT access/refresh secrets are required")
	}
	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return errors.New("token TTL must be > 0")
	}
	if c.Issuer == "" {
		c.Issuer = "authkit"
	}
	if c.RBACAdminPermission == "" {
		c.RBACAdminPermission = "rbac.manage"
	}
	if err := c.AuthZ.validate(); err != nil {
		return err
	}
	return nil
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
