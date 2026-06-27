package auth

import (
	"os"
	"strings"
)

// ApplyEnv fills auth configuration from standard environment variables.
// Call after DefaultConfig() and before Open().
func ApplyEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	if v := strings.TrimSpace(os.Getenv("JWT_ACCESS_SECRET")); v != "" {
		cfg.JWTAccessSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("JWT_REFRESH_SECRET")); v != "" {
		cfg.JWTRefreshSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("DATA_ENCRYPTION_KEY_B64")); v != "" {
		cfg.DataEncryptionKeyB64 = v
	}
	if v := strings.TrimSpace(os.Getenv("JWT_ISSUER")); v != "" {
		cfg.Issuer = v
	}
	if v := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); v != "" {
		cfg.PublicBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("FRONTEND_BASE_URL")); v != "" {
		cfg.FrontendBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID")); v != "" {
		cfg.GoogleClientID = v
	}
	if v := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET")); v != "" {
		cfg.GoogleClientSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("GOOGLE_REDIRECT_URL")); v != "" {
		cfg.GoogleRedirectURL = v
	}

	cfg.ApplyDefaults()
	if cfg.GoogleRedirectURL == "" && cfg.PublicBaseURL != "" {
		cfg.GoogleRedirectURL = strings.TrimRight(cfg.PublicBaseURL, "/") + "/auth/oauth/google/callback"
	}
	if cfg.FrontendBaseURL == "" {
		cfg.FrontendBaseURL = cfg.PublicBaseURL
	}
}

// GoogleOAuthConfigured reports whether Google OAuth env/config is complete.
func (c Config) GoogleOAuthConfigured() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != "" && c.GoogleRedirectURL != ""
}
