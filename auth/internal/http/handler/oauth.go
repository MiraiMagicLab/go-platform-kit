package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	login "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/login"
	oauthuc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/validate"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// OAuthHandler handles OAuth endpoints.
type OAuthHandler struct {
	oauthSvc     *oauthuc.OAuthService
	authSvc      *login.AuthService
	cookiePath   string
	frontendBase string
	cookieSecure bool
	lifecycle    *Lifecycle
}

// NewOAuthHandler creates an OAuthHandler for Google and Facebook OAuth2 login flows.
func NewOAuthHandler(
	oauthSvc *oauthuc.OAuthService,
	authSvc *login.AuthService,
	cookiePath string,
	frontendBase string,
	cookieSecure bool,
	lifecycle *Lifecycle,
) *OAuthHandler {
	return &OAuthHandler{
		oauthSvc:     oauthSvc,
		authSvc:      authSvc,
		cookiePath:   cookiePath,
		frontendBase: frontendBase,
		cookieSecure: cookieSecure,
		lifecycle:    lifecycle,
	}
}

// Login handles GET /oauth/:provider/login.
func (h *OAuthHandler) Login(c *gin.Context) {
	provider := oauthuc.Provider(c.Param("provider"))
	state := uuid.New().String()
	url, err := h.oauthSvc.AuthCodeURL(provider, state)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	validate.SetOAuthStateCookie(c, "oauth_state_"+string(provider), state, h.cookiePath, h.cookieSecure)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Callback handles GET /oauth/:provider/callback.
func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := oauthuc.Provider(c.Param("provider"))
	state := c.Query("state")
	code := c.Query("code")
	if code == "" {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	cookieName := "oauth_state_" + string(provider)
	savedState, err := c.Cookie(cookieName)
	if err != nil || savedState != state {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthStateInvalid, nil)
		return
	}
	validate.ClearOAuthStateCookie(c, cookieName, h.cookiePath, h.cookieSecure)

	identity, err := h.oauthSvc.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthExchangeFail, nil)
		return
	}
	userID, err := h.oauthSvc.FindOrCreateUserForIdentity(c.Request.Context(), identity)
	if err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeOAuthUserFail, nil)
		return
	}

	res, err := h.authSvc.StartSession(c.Request.Context(), userID, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	}, "")
	if err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, c, "oauth", userID.String(), nil, c.ClientIP(), c.Request.UserAgent())

	redirectURL := h.frontendBase + "/auth/oauth/callback"
	redirectURL += "?access_token=" + res.AccessToken
	redirectURL += "&refresh_token=" + res.RefreshToken
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}
