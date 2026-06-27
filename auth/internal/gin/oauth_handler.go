package gin

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	authsvc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/auth"
	oauthSvc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/util"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// OAuthHandler handles OAuth endpoints.
type OAuthHandler struct {
	oauthSvc     *oauthSvc.OAuthService
	authSvc      *authsvc.AuthService
	cookiePath   string
	frontendBase string
	cookieSecure bool
	lifecycle    *Lifecycle
}

// NewOAuthHandler creates an OAuthHandler for Google and Facebook OAuth2 login flows.
func NewOAuthHandler(
	oauthSvc *oauthSvc.OAuthService,
	authSvc *authsvc.AuthService,
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

// Login handles GET /oauth/:provider/login. It redirects the user to the
// OAuth provider's consent page with a CSRF state cookie.
func (h *OAuthHandler) Login(c *gin.Context) {
	provider := oauthSvc.Provider(c.Param("provider"))
	state := uuid.New().String()
	url, err := h.oauthSvc.AuthCodeURL(provider, state)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeOAuthNotConfigured, nil)
		return
	}
	util.SetOAuthStateCookie(c, "oauth_state_"+string(provider), state, h.cookiePath, h.cookieSecure)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Callback handles GET /oauth/:provider/callback. It validates the CSRF state,
// exchanges the authorization code for tokens, finds or creates the user,
// issues a session, and redirects to the frontend with tokens.
func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := oauthSvc.Provider(c.Param("provider"))
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
	util.ClearOAuthStateCookie(c, cookieName, h.cookiePath, h.cookieSecure)

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
