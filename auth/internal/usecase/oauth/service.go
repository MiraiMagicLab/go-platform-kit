package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var ErrOAuthNotConfigured = errors.New("oauth not configured")

// Provider represents an OAuth provider.
type Provider string

const (
	ProviderGoogle   Provider = "google"
	ProviderFacebook Provider = "facebook"
)

// Identity represents a fetched OAuth identity from a provider.
type Identity struct {
	Provider        Provider
	ProviderSubject string
	Email           string
}

// OAuthService handles OAuth2 flows for Google and Facebook.
type OAuthService struct {
	identities  ports.IdentityRepository
	users       ports.UserRepository
	googleCfg   *oauth2.Config
	facebookCfg *oauth2.Config
	httpClient  *http.Client
}

func NewOAuthService(identities ports.IdentityRepository, users ports.UserRepository, googleCfg, facebookCfg *oauth2.Config) *OAuthService {
	return &OAuthService{
		identities:  identities,
		users:       users,
		googleCfg:   googleCfg,
		facebookCfg: facebookCfg,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *OAuthService) AuthCodeURL(provider Provider, state string) (string, error) {
	cfg, err := s.cfg(provider)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *OAuthService) ExchangeAndFetchIdentity(ctx context.Context, provider Provider, code string) (Identity, error) {
	cfg, err := s.cfg(provider)
	if err != nil {
		return Identity{}, err
	}
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return Identity{}, err
	}

	switch provider {
	case ProviderGoogle:
		return s.fetchGoogleIdentity(ctx, tok)
	case ProviderFacebook:
		return s.fetchFacebookIdentity(ctx, tok)
	default:
		return Identity{}, errors.New("unsupported provider")
	}
}

func (s *OAuthService) FindOrCreateUserForIdentity(ctx context.Context, id Identity) (uuid.UUID, error) {
	if id.ProviderSubject == "" {
		return uuid.Nil, errors.New("missing subject")
	}
	if id.Email == "" {
		id.Email = fmt.Sprintf("%s_%s@example.invalid", id.Provider, id.ProviderSubject)
	}

	if uid, ok, err := s.identities.FindUserIDByProvider(ctx, string(id.Provider), id.ProviderSubject); err != nil {
		return uuid.Nil, err
	} else if ok {
		if id.Email != "" {
			_ = s.users.SetEmailVerified(ctx, uid, true)
		}
		return uid, nil
	}

	randomPass := uuid.New().String()
	pwHash, err := bcrypt.GenerateFromPassword([]byte(randomPass), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, err
	}
	userID, err := s.users.CreateOAuthUser(ctx, strings.ToLower(id.Email), string(pwHash))
	if err != nil {
		return uuid.Nil, err
	}
	_ = s.users.SetEmailVerified(ctx, userID, true)
	_ = s.identities.LinkIdentity(ctx, userID, string(id.Provider), id.ProviderSubject, id.Email)
	return userID, nil
}

func (s *OAuthService) cfg(provider Provider) (*oauth2.Config, error) {
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

func (s *OAuthService) fetchGoogleIdentity(ctx context.Context, tok *oauth2.Token) (Identity, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Identity{}, errors.New("failed to fetch userinfo")
	}

	var u struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return Identity{}, err
	}
	return Identity{Provider: ProviderGoogle, ProviderSubject: u.Sub, Email: u.Email}, nil
}

func (s *OAuthService) fetchFacebookIdentity(ctx context.Context, tok *oauth2.Token) (Identity, error) {
	url := "https://graph.facebook.com/me?fields=id,email&access_token=" + tok.AccessToken
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Identity{}, errors.New("failed to fetch userinfo")
	}

	var u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return Identity{}, err
	}
	return Identity{Provider: ProviderFacebook, ProviderSubject: u.ID, Email: u.Email}, nil
}
