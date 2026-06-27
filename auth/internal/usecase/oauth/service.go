package oauth

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

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

var (
	ErrOAuthNotConfigured    = errors.New("oauth not configured")
	ErrUnsupportedProvider   = errors.New("unsupported oauth provider")
	ErrGoogleEmailNotVerified = errors.New("google email not verified")
	ErrGoogleEmailMissing    = errors.New("google email missing")
)

// Provider represents an OAuth provider. Only Google is supported.
type Provider string

const ProviderGoogle Provider = "google"

// Identity represents a fetched OAuth identity from Google.
type Identity struct {
	Provider        Provider
	ProviderSubject string
	Email           string
	EmailVerified   bool
	Name            string
	Picture         string
}

// OAuthService handles Google OAuth2 sign-in.
type OAuthService struct {
	identities       ports.IdentityRepository
	users            ports.UserRepository
	googleCfg        *oauth2.Config
	httpClient       *http.Client
	googleUserInfoURL string
}

// Option configures OAuthService.
type Option func(*OAuthService)

// WithHTTPClient overrides the HTTP client used for Google userinfo requests.
func WithHTTPClient(c *http.Client) Option {
	return func(s *OAuthService) {
		if c != nil {
			s.httpClient = c
		}
	}
}

// WithGoogleUserInfoURL overrides the Google userinfo endpoint (for tests).
func WithGoogleUserInfoURL(url string) Option {
	return func(s *OAuthService) {
		if url != "" {
			s.googleUserInfoURL = url
		}
	}
}

// NewOAuthService creates a Google OAuth service.
func NewOAuthService(identities ports.IdentityRepository, users ports.UserRepository, googleCfg *oauth2.Config, opts ...Option) *OAuthService {
	s := &OAuthService{
		identities:        identities,
		users:             users,
		googleCfg:         googleCfg,
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		googleUserInfoURL: googleUserInfoEndpoint,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GoogleConfigured reports whether Google OAuth is ready.
func (s *OAuthService) GoogleConfigured() bool {
	return IsGoogleConfigured(s.googleCfg)
}

func (s *OAuthService) requireGoogle(provider Provider) error {
	if provider != ProviderGoogle {
		return ErrUnsupportedProvider
	}
	if !IsGoogleConfigured(s.googleCfg) {
		return ErrOAuthNotConfigured
	}
	return nil
}

// AuthCodeURL returns the Google consent URL for the given CSRF state.
func (s *OAuthService) AuthCodeURL(provider Provider, state string) (string, error) {
	if err := s.requireGoogle(provider); err != nil {
		return "", err
	}
	return s.googleCfg.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.ApprovalForce), nil
}

// ExchangeAndFetchIdentity exchanges an authorization code and loads the Google profile.
func (s *OAuthService) ExchangeAndFetchIdentity(ctx context.Context, provider Provider, code string) (Identity, error) {
	if err := s.requireGoogle(provider); err != nil {
		return Identity{}, err
	}
	tok, err := s.googleCfg.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("google token exchange: %w", err)
	}
	return s.fetchGoogleIdentity(ctx, tok)
}

// FindOrCreateUserForIdentity links or creates a local user for a Google identity.
// The second return value is true when a new user account was created.
func (s *OAuthService) FindOrCreateUserForIdentity(ctx context.Context, id Identity) (uuid.UUID, bool, error) {
	if id.Provider != ProviderGoogle {
		return uuid.Nil, false, ErrUnsupportedProvider
	}
	if id.ProviderSubject == "" {
		return uuid.Nil, false, errors.New("missing subject")
	}
	if id.Email == "" {
		return uuid.Nil, false, ErrGoogleEmailMissing
	}
	if !id.EmailVerified {
		return uuid.Nil, false, ErrGoogleEmailNotVerified
	}

	if uid, ok, err := s.identities.FindUserIDByProvider(ctx, string(id.Provider), id.ProviderSubject); err != nil {
		return uuid.Nil, false, err
	} else if ok {
		_ = s.users.SetEmailVerified(ctx, uid, true)
		return uid, false, nil
	}

	randomPass := uuid.New().String()
	pwHash, err := bcrypt.GenerateFromPassword([]byte(randomPass), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, false, err
	}
	userID, err := s.users.CreateOAuthUser(ctx, strings.ToLower(id.Email), string(pwHash))
	if err != nil {
		return uuid.Nil, false, err
	}
	_ = s.users.SetEmailVerified(ctx, userID, true)
	_ = s.identities.LinkIdentity(ctx, userID, string(id.Provider), id.ProviderSubject, id.Email)
	return userID, true, nil
}

func (s *OAuthService) fetchGoogleIdentity(ctx context.Context, tok *oauth2.Token) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.googleUserInfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return Identity{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("google userinfo: status %d", resp.StatusCode)
	}

	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(b, &u); err != nil {
		return Identity{}, err
	}
	if u.Sub == "" {
		return Identity{}, errors.New("google userinfo: missing sub")
	}

	return Identity{
		Provider:        ProviderGoogle,
		ProviderSubject: u.Sub,
		Email:           u.Email,
		EmailVerified:   u.EmailVerified,
		Name:            u.Name,
		Picture:         u.Picture,
	}, nil
}

// MapExchangeError converts low-level OAuth errors to domain errors when appropriate.
func MapExchangeError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrGoogleEmailNotVerified):
		return domain.ErrEmailNotVerified{}
	case errors.Is(err, ErrGoogleEmailMissing):
		return domain.ErrInvalidCredentials
	default:
		return err
	}
}
