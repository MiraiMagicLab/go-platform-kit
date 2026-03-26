package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/tienh/authsvc/internal/repository"
)

var ErrOAuthNotConfigured = errors.New("oauth not configured")

type OAuthProvider string

const (
	ProviderGoogle   OAuthProvider = "google"
	ProviderFacebook OAuthProvider = "facebook"
)

type OAuthService struct {
	identities repository.IdentityRepository
	users      repository.UserRepository

	googleCfg   *oauth2.Config
	facebookCfg *oauth2.Config
	httpClient  *http.Client
}

func NewOAuthService(identities repository.IdentityRepository, users repository.UserRepository, googleCfg, facebookCfg *oauth2.Config) *OAuthService {
	return &OAuthService{
		identities:  identities,
		users:       users,
		googleCfg:   googleCfg,
		facebookCfg: facebookCfg,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *OAuthService) AuthCodeURL(provider OAuthProvider, state string) (string, error) {
	cfg, err := s.cfg(provider)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

type OAuthIdentity struct {
	Provider        OAuthProvider
	ProviderSubject string
	Email           string
}

func (s *OAuthService) ExchangeAndFetchIdentity(ctx context.Context, provider OAuthProvider, code string) (OAuthIdentity, error) {
	cfg, err := s.cfg(provider)
	if err != nil {
		return OAuthIdentity{}, err
	}
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return OAuthIdentity{}, err
	}

	switch provider {
	case ProviderGoogle:
		return s.fetchGoogleIdentity(ctx, tok)
	case ProviderFacebook:
		return s.fetchFacebookIdentity(ctx, tok)
	default:
		return OAuthIdentity{}, errors.New("unsupported provider")
	}
}

func (s *OAuthService) FindOrCreateUserForIdentity(ctx context.Context, id OAuthIdentity) (uuid.UUID, error) {
	if id.ProviderSubject == "" {
		return uuid.Nil, errors.New("missing subject")
	}
	if id.Email == "" {
		id.Email = fmt.Sprintf("%s_%s@example.invalid", id.Provider, id.ProviderSubject)
	}

	if uid, ok, err := s.identities.FindUserIDByProvider(ctx, string(id.Provider), id.ProviderSubject); err != nil {
		return uuid.Nil, err
	} else if ok {
		return uid, nil
	}

	// Create a user with password login disabled. Password hash is random to satisfy schema.
	randomPass := uuid.New().String()
	pwHash, err := bcryptHash(randomPass)
	if err != nil {
		return uuid.Nil, err
	}
	userID, err := s.users.CreateOAuthUser(ctx, strings.ToLower(id.Email), pwHash)
	if err != nil {
		return uuid.Nil, err
	}
	_ = s.identities.LinkIdentity(ctx, userID, string(id.Provider), id.ProviderSubject, id.Email)
	return userID, nil
}

func (s *OAuthService) cfg(provider OAuthProvider) (*oauth2.Config, error) {
	switch provider {
	case ProviderGoogle:
		if s.googleCfg == nil {
			return nil, ErrOAuthNotConfigured
		}
		return s.googleCfg, nil
	case ProviderFacebook:
		if s.facebookCfg == nil {
			return nil, ErrOAuthNotConfigured
		}
		return s.facebookCfg, nil
	default:
		return nil, errors.New("unsupported provider")
	}
}

func (s *OAuthService) fetchGoogleIdentity(ctx context.Context, tok *oauth2.Token) (OAuthIdentity, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return OAuthIdentity{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OAuthIdentity{}, errors.New("failed to fetch userinfo")
	}

	var u struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return OAuthIdentity{}, err
	}
	return OAuthIdentity{Provider: ProviderGoogle, ProviderSubject: u.Sub, Email: u.Email}, nil
}

func (s *OAuthService) fetchFacebookIdentity(ctx context.Context, tok *oauth2.Token) (OAuthIdentity, error) {
	url := "https://graph.facebook.com/me?fields=id,email&access_token=" + tok.AccessToken
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return OAuthIdentity{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OAuthIdentity{}, errors.New("failed to fetch userinfo")
	}

	var u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return OAuthIdentity{}, err
	}
	return OAuthIdentity{Provider: ProviderFacebook, ProviderSubject: u.ID, Email: u.Email}, nil
}

func bcryptHash(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

var _ = google.Endpoint
