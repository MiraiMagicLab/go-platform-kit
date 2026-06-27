package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
)

func googleTestConfig(tokenURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost/auth/oauth/google/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: tokenURL,
		},
		Scopes: oauth.GoogleScopes,
	}
}

func TestFindOrCreateUserForIdentityExisting(t *testing.T) {
	users := testmem.NewUsers()
	identities := testmem.NewIdentity()
	svc := oauth.NewOAuthService(identities, users, nil)

	userID, err := users.CreateOAuthUser(context.Background(), "existing@example.com", "hash")
	require.NoError(t, err)
	require.NoError(t, identities.LinkIdentity(context.Background(), userID, "google", "sub-123", "existing@example.com"))

	got, created, err := svc.FindOrCreateUserForIdentity(context.Background(), oauth.Identity{
		Provider: oauth.ProviderGoogle, ProviderSubject: "sub-123", Email: "existing@example.com", EmailVerified: true,
	})
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, userID, got)

	u, err := users.GetByID(context.Background(), got)
	require.NoError(t, err)
	require.True(t, u.EmailVerified)
}

func TestFindOrCreateUserForIdentityCreatesNew(t *testing.T) {
	users := testmem.NewUsers()
	identities := testmem.NewIdentity()
	svc := oauth.NewOAuthService(identities, users, nil)

	got, created, err := svc.FindOrCreateUserForIdentity(context.Background(), oauth.Identity{
		Provider: oauth.ProviderGoogle, ProviderSubject: "sub-new", Email: "new@example.com", EmailVerified: true,
	})
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, got.String(), "00000000-0000-0000-0000-000000000000")

	linked, ok, err := identities.FindUserIDByProvider(context.Background(), "google", "sub-new")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, got, linked)
}

func TestFindOrCreateUserRejectsUnverifiedEmail(t *testing.T) {
	svc := oauth.NewOAuthService(testmem.NewIdentity(), testmem.NewUsers(), nil)
	_, _, err := svc.FindOrCreateUserForIdentity(context.Background(), oauth.Identity{
		Provider: oauth.ProviderGoogle, ProviderSubject: "sub", Email: "a@b.c", EmailVerified: false,
	})
	require.ErrorIs(t, err, oauth.ErrGoogleEmailNotVerified)
}

func TestAuthCodeURLOAuthNotConfigured(t *testing.T) {
	svc := oauth.NewOAuthService(testmem.NewIdentity(), testmem.NewUsers(), nil)
	_, err := svc.AuthCodeURL(oauth.ProviderGoogle, "state")
	require.ErrorIs(t, err, oauth.ErrOAuthNotConfigured)
}

func TestAuthCodeURLGoogle(t *testing.T) {
	cfg := googleTestConfig("https://oauth2.googleapis.com/token")
	svc := oauth.NewOAuthService(testmem.NewIdentity(), testmem.NewUsers(), cfg)
	url, err := svc.AuthCodeURL(oauth.ProviderGoogle, "csrf-state")
	require.NoError(t, err)
	require.Contains(t, url, "accounts.google.com")
	require.Contains(t, url, "state=csrf-state")
}

func TestAuthCodeURLRejectsUnsupportedProvider(t *testing.T) {
	cfg := googleTestConfig("https://oauth2.googleapis.com/token")
	svc := oauth.NewOAuthService(testmem.NewIdentity(), testmem.NewUsers(), cfg)
	_, err := svc.AuthCodeURL(oauth.Provider("facebook"), "state")
	require.ErrorIs(t, err, oauth.ErrUnsupportedProvider)
}

func TestExchangeAndFetchGoogleIdentity(t *testing.T) {
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            "google-sub-1",
			"email":          "user@gmail.com",
			"email_verified": true,
			"name":           "Test User",
		})
	}))
	defer userinfo.Close()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	cfg := googleTestConfig(tokenSrv.URL)
	svc := oauth.NewOAuthService(testmem.NewIdentity(), testmem.NewUsers(), cfg, oauth.WithGoogleUserInfoURL(userinfo.URL))

	id, err := svc.ExchangeAndFetchIdentity(context.Background(), oauth.ProviderGoogle, "auth-code")
	require.NoError(t, err)
	require.Equal(t, oauth.ProviderGoogle, id.Provider)
	require.Equal(t, "google-sub-1", id.ProviderSubject)
	require.Equal(t, "user@gmail.com", id.Email)
	require.True(t, id.EmailVerified)
}

func TestNewGoogleOAuthConfig(t *testing.T) {
	cfg := oauth.NewGoogleOAuthConfig("id", "secret", "http://localhost/cb")
	require.NotNil(t, cfg)
	require.Equal(t, google.Endpoint.AuthURL, cfg.Endpoint.AuthURL)
	require.True(t, oauth.IsGoogleConfigured(cfg))
	require.False(t, oauth.IsGoogleConfigured(nil))
}
