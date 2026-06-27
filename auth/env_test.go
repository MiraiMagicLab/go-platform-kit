package auth_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
)

func TestApplyEnvGoogleOAuth(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "google-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "google-secret")
	t.Setenv("PUBLIC_BASE_URL", "http://localhost:8080")

	cfg := auth.DefaultConfig()
	auth.ApplyEnv(&cfg)

	require.Equal(t, "google-id", cfg.GoogleClientID)
	require.Equal(t, "google-secret", cfg.GoogleClientSecret)
	require.Equal(t, "http://localhost:8080/auth/oauth/google/callback", cfg.GoogleRedirectURL)
	require.True(t, cfg.GoogleOAuthConfigured())
}

func TestApplyEnvGoogleRedirectOverride(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "secret")
	t.Setenv("GOOGLE_REDIRECT_URL", "https://api.example.com/auth/oauth/google/callback")

	cfg := auth.DefaultConfig()
	auth.ApplyEnv(&cfg)
	require.Equal(t, "https://api.example.com/auth/oauth/google/callback", cfg.GoogleRedirectURL)
}

func TestApplyEnvNoPanicWithNil(t *testing.T) {
	auth.ApplyEnv(nil)
	_ = os.Getenv("PATH")
}
