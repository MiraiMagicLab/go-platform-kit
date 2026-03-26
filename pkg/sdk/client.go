package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type Option func(*Client)

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type TokenStore interface {
	Get() (accessToken string, refreshToken string)
	Set(accessToken, refreshToken string)
}

type MemoryTokenStore struct {
	mu      sync.RWMutex
	access  string
	refresh string
}

func (m *MemoryTokenStore) Get() (string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.access, m.refresh
}

func (m *MemoryTokenStore) Set(accessToken, refreshToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if accessToken != "" {
		m.access = accessToken
	}
	if refreshToken != "" {
		m.refresh = refreshToken
	}
}

type AutoRefreshTransport struct {
	Base       http.RoundTripper
	Client     *Client
	TokenStore TokenStore
	mu         sync.Mutex
}

func (t *AutoRefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	access, _ := t.TokenStore.Get()
	req1 := cloneRequest(req)
	if access != "" {
		req1.Header.Set("Authorization", "Bearer "+access)
	}
	resp, err := base.RoundTrip(req1)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	_ = resp.Body.Close()

	t.mu.Lock()
	defer t.mu.Unlock()

	access, refresh := t.TokenStore.Get()
	if refresh == "" {
		return resp, nil
	}
	tokens, err := t.Client.Refresh(req.Context(), refresh)
	if err != nil {
		return resp, nil
	}
	t.TokenStore.Set(tokens.AccessToken, tokens.RefreshToken)

	req2 := cloneRequest(req)
	req2.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	return base.RoundTrip(req2)
}

func cloneRequest(req *http.Request) *http.Request {
	r := req.Clone(req.Context())
	r.Header = req.Header.Clone()
	return r
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type IDResponse struct {
	ID string `json:"id"`
}

func (c *Client) Register(ctx context.Context, req RegisterRequest) (IDResponse, error) {
	var out IDResponse
	if err := c.doJSON(ctx, http.MethodPost, "/register", req, &out, "", nil); err != nil {
		return IDResponse{}, err
	}
	return out, nil
}

type LoginResponse struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"`
}

type TokenPair struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (c *Client) Login(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	var out LoginResponse
	if err := c.doJSON(ctx, http.MethodPost, "/login", req, &out, "", nil); err != nil {
		return LoginResponse{}, err
	}
	return out, nil
}

type CompleteMFARequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

func (c *Client) CompleteMFA(ctx context.Context, req CompleteMFARequest) (TokenPair, error) {
	var out TokenPair
	if err := c.doJSON(ctx, http.MethodPost, "/login/2fa", req, &out, "", nil); err != nil {
		return TokenPair{}, err
	}
	return out, nil
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	var out TokenPair
	if err := c.doJSON(ctx, http.MethodPost, "/refresh", RefreshRequest{RefreshToken: refreshToken}, &out, "", nil); err != nil {
		return TokenPair{}, err
	}
	return out, nil
}

type MeResponse struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (c *Client) Me(ctx context.Context, accessToken string) (MeResponse, error) {
	var out MeResponse
	if err := c.doJSON(ctx, http.MethodGet, "/me", nil, &out, accessToken, nil); err != nil {
		return MeResponse{}, err
	}
	return out, nil
}

func (c *Client) Logout(ctx context.Context, accessToken string) error {
	return c.doJSON(ctx, http.MethodPost, "/logout", nil, nil, accessToken, nil)
}

type MFASetupResponse struct {
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

func (c *Client) MFASetup(ctx context.Context, accessToken string) (MFASetupResponse, error) {
	var out MFASetupResponse
	if err := c.doJSON(ctx, http.MethodPost, "/mfa/setup", nil, &out, accessToken, nil); err != nil {
		return MFASetupResponse{}, err
	}
	return out, nil
}

func (c *Client) MFAEnable(ctx context.Context, accessToken, code string) error {
	return c.doJSON(ctx, http.MethodPost, "/mfa/enable", map[string]string{"code": code}, nil, accessToken, nil)
}

func (c *Client) MFADisable(ctx context.Context, accessToken string) error {
	return c.doJSON(ctx, http.MethodPost, "/mfa/disable", nil, nil, accessToken, nil)
}

func (c *Client) CreateRole(ctx context.Context, accessToken, name string) (IDResponse, error) {
	var out IDResponse
	if err := c.doJSON(ctx, http.MethodPost, "/roles", map[string]string{"name": name}, &out, accessToken, nil); err != nil {
		return IDResponse{}, err
	}
	return out, nil
}

func (c *Client) CreatePermission(ctx context.Context, accessToken, name string) (IDResponse, error) {
	var out IDResponse
	if err := c.doJSON(ctx, http.MethodPost, "/permissions", map[string]string{"name": name}, &out, accessToken, nil); err != nil {
		return IDResponse{}, err
	}
	return out, nil
}

func (c *Client) AssignRolePermissions(ctx context.Context, accessToken, roleID string, permissionIDs []string) error {
	return c.doJSON(ctx, http.MethodPost, "/roles/"+url.PathEscape(roleID)+"/permissions", map[string][]string{"permission_ids": permissionIDs}, nil, accessToken, nil)
}

func (c *Client) AssignUserRoles(ctx context.Context, accessToken, userID string, roleIDs []string) error {
	return c.doJSON(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/roles", map[string][]string{"role_ids": roleIDs}, nil, accessToken, nil)
}

func (c *Client) LoginURL(provider string) string {
	return c.baseURL + "/oauth/" + url.PathEscape(provider) + "/login"
}

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("authsdk: http %d: %s", e.StatusCode, e.Body)
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, out any, accessToken string, headers map[string]string) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
