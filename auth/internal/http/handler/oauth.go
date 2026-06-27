package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	login "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/login"
	oauthuc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/validate"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// OAuthHandler handles Google OAuth endpoints.
type OAuthHandler struct {
	oauthSvc     *oauthuc.OAuthService
	authSvc      *login.AuthService
	rbacSvc      *rbac.RBACService
	defaultRole  string
	cookiePath   string
	frontendBase string
	cookieSecure bool
	lifecycle    *Lifecycle
}

// NewOAuthHandler creates an OAuthHandler for Google OAuth2 login flows.
func NewOAuthHandler(
	oauthSvc *oauthuc.OAuthService,
	authSvc *login.AuthService,
	rbacSvc *rbac.RBACService,
	defaultRole string,
	cookiePath string,
	frontendBase string,
	cookieSecure bool,
	lifecycle *Lifecycle,
) *OAuthHandler {
	return &OAuthHandler{
		oauthSvc:     oauthSvc,
		authSvc:      authSvc,
		rbacSvc:      rbacSvc,
		defaultRole:  defaultRole,
		cookiePath:   cookiePath,
		frontendBase: frontendBase,
		cookieSecure: cookieSecure,
		lifecycle:    lifecycle,
	}
}

// Login handles GET /oauth/google/login.
func (h *OAuthHandler) Login(c *gin.Context) {
	if err := h.requireGoogleProvider(c.Param("provider")); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	if !h.oauthSvc.GoogleConfigured() {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}

	state := uuid.New().String()
	authURL, err := h.oauthSvc.AuthCodeURL(oauthuc.ProviderGoogle, state)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	validate.SetOAuthStateCookie(c, oauthStateCookieName(), state, h.cookiePath, h.cookieSecure)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles GET /oauth/google/callback.
func (h *OAuthHandler) Callback(c *gin.Context) {
	if err := h.requireGoogleProvider(c.Param("provider")); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	if errMsg := c.Query("error"); errMsg != "" {
		h.redirectOAuthError(c, errMsg)
		return
	}

	state := c.Query("state")
	code := c.Query("code")
	if code == "" {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	savedState, err := c.Cookie(oauthStateCookieName())
	if err != nil || savedState != state {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthStateInvalid, nil)
		return
	}
	validate.ClearOAuthStateCookie(c, oauthStateCookieName(), h.cookiePath, h.cookieSecure)

	res, userID, err := h.completeGoogleOAuth(c, code)
	if err != nil {
		if writeOAuthExchangeError(c, err) {
			return
		}
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeOAuthUserFail, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, c, "oauth", userID.String(), nil, c.ClientIP(), c.Request.UserAgent())
	h.redirectOAuthSuccess(c, res)
}

type oauthExchangeReq struct {
	Code string `json:"code" binding:"required"`
}

// Exchange handles POST /oauth/google/exchange for SPA/mobile clients that receive the auth code directly.
func (h *OAuthHandler) Exchange(c *gin.Context) {
	if err := h.requireGoogleProvider(c.Param("provider")); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	var req oauthExchangeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	savedState, err := c.Cookie(oauthStateCookieName())
	if err != nil || savedState == "" {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthStateInvalid, nil)
		return
	}
	validate.ClearOAuthStateCookie(c, oauthStateCookieName(), h.cookiePath, h.cookieSecure)

	res, userID, err := h.completeGoogleOAuth(c, req.Code)
	if err != nil {
		if writeOAuthExchangeError(c, err) {
			return
		}
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeOAuthUserFail, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, c, "oauth", userID.String(), nil, c.ClientIP(), c.Request.UserAgent())
	httpx.Success(c, http.StatusOK, "success", res, nil)
}

func (h *OAuthHandler) completeGoogleOAuth(c *gin.Context, code string) (login.LoginResult, uuid.UUID, error) {
	identity, err := h.oauthSvc.ExchangeAndFetchIdentity(c.Request.Context(), oauthuc.ProviderGoogle, code)
	if err != nil {
		return login.LoginResult{}, uuid.Nil, err
	}
	userID, created, err := h.oauthSvc.FindOrCreateUserForIdentity(c.Request.Context(), identity)
	if err != nil {
		return login.LoginResult{}, uuid.Nil, err
	}
	if created && h.defaultRole != "" && h.rbacSvc != nil {
		_ = h.rbacSvc.AssignRoleByName(c.Request.Context(), userID, h.defaultRole)
	}
	res, err := h.authSvc.StartSession(c.Request.Context(), userID, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	}, "")
	if err != nil {
		return login.LoginResult{}, uuid.Nil, err
	}
	return res, userID, nil
}

func (h *OAuthHandler) requireGoogleProvider(provider string) error {
	if oauthuc.Provider(provider) != oauthuc.ProviderGoogle {
		return oauthuc.ErrUnsupportedProvider
	}
	return nil
}

func oauthStateCookieName() string {
	return "oauth_state_google"
}

func (h *OAuthHandler) redirectOAuthSuccess(c *gin.Context, res login.LoginResult) {
	base := strings.TrimRight(h.frontendBase, "/") + "/auth/oauth/callback"
	fragment := url.Values{}
	fragment.Set("access_token", res.AccessToken)
	fragment.Set("refresh_token", res.RefreshToken)
	c.Redirect(http.StatusTemporaryRedirect, base+"#"+fragment.Encode())
}

func (h *OAuthHandler) redirectOAuthError(c *gin.Context, providerError string) {
	base := strings.TrimRight(h.frontendBase, "/") + "/auth/oauth/callback"
	fragment := url.Values{}
	fragment.Set("error", providerError)
	c.Redirect(http.StatusTemporaryRedirect, base+"#"+fragment.Encode())
}

func writeOAuthExchangeError(c *gin.Context, err error) bool {
	switch {
	case err == oauthuc.ErrOAuthNotConfigured, err == oauthuc.ErrUnsupportedProvider:
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return true
	case err == oauthuc.ErrGoogleEmailNotVerified:
		httpx.FailCode(c, http.StatusForbidden, httpx.CodeAuthEmailNotVerified, nil)
		return true
	case err == oauthuc.ErrGoogleEmailMissing:
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthExchangeFail, nil)
		return true
	default:
		if _, ok := err.(domain.ErrEmailNotVerified); ok {
			httpx.FailCode(c, http.StatusForbidden, httpx.CodeAuthEmailNotVerified, nil)
			return true
		}
		if isOAuthExchangeFailure(err) {
			httpx.FailCode(c, http.StatusBadGateway, httpx.CodeOAuthExchangeFail, nil)
			return true
		}
	}
	return false
}

func isOAuthExchangeFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "token exchange") || strings.Contains(msg, "userinfo")
}