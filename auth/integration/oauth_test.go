//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func openTestAuthWithGoogleOAuth(t *testing.T, tokenURL, userinfoURL string) (context.Context, *auth.Auth, func()) {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}

	pg, err := postgres.Open(ctx, postgres.Config{URL: url})
	require.NoError(t, err)
	ensureBaselineSchema(t, ctx, pg)

	cfg := auth.DefaultConfig()
	cfg.JWTAccessSecret = "test-access-secret"
	cfg.JWTRefreshSecret = "test-refresh-secret"
	cfg.GoogleClientID = "test-client-id"
	cfg.GoogleClientSecret = "test-client-secret"
	cfg.GoogleRedirectURL = "http://localhost/auth/oauth/google/callback"

	a, err := auth.Open(ctx,
		auth.WithConfig(cfg),
		auth.WithPostgres(pg),
		auth.WithGoogleOAuthTokenURL(tokenURL),
		auth.WithOAuthOptions(oauth.WithGoogleUserInfoURL(userinfoURL)),
	)
	require.NoError(t, err)
	return ctx, a, func() { pg.Close() }
}

func TestAuthGoogleOAuthExchange(t *testing.T) {
	suffix := strings.ReplaceAll(uniqueEmail("oauth"), "@example.com", "")
	subject := "google-" + suffix
	email := subject + "@gmail.com"

	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer mock-access-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            subject,
			"email":          email,
			"email_verified": true,
			"name":           "OAuth User",
		})
	}))
	defer userinfo.Close()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	ctx, a, cleanup := openTestAuthWithGoogleOAuth(t, tokenSrv.URL, userinfo.URL)
	defer cleanup()

	meta := auth.ClientMeta{IP: "127.0.0.1", UA: "integration-oauth"}
	res, err := a.OAuthExchange(ctx, auth.OAuthGoogle, "mock-auth-code", meta)
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)

	roles, err := a.ListUserRoles(ctx, res.UserID)
	require.NoError(t, err)
	require.Contains(t, roles, "user")

	res2, err := a.OAuthExchange(ctx, auth.OAuthGoogle, "mock-auth-code-2", meta)
	require.NoError(t, err)
	require.Equal(t, res.UserID, res2.UserID)
}

func TestAuthGoogleOAuthRejectsUnverifiedEmail(t *testing.T) {
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub": "sub-1", "email": "a@b.c", "email_verified": false,
		})
	}))
	defer userinfo.Close()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "t", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer tokenSrv.Close()

	ctx, a, cleanup := openTestAuthWithGoogleOAuth(t, tokenSrv.URL, userinfo.URL)
	defer cleanup()

	_, err := a.OAuthExchange(ctx, auth.OAuthGoogle, "code", auth.ClientMeta{})
	require.Error(t, err)
}
