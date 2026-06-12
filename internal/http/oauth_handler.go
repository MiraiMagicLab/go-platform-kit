package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/auth"
	oauthSvc "github.com/MiraiMagicLab/go-platform-kit/v2/internal/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/utils"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/response"
)

// OAuthHandler handles OAuth endpoints.
type OAuthHandler struct {
	oauthSvc     *oauthSvc.OAuthService
	authSvc      *auth.AuthService
	cookiePath   string
	frontendBase string
	cookieSecure bool
	lifecycle    *Lifecycle
}

func NewOAuthHandler(
	oauthSvc *oauthSvc.OAuthService,
	authSvc *auth.AuthService,
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

func (h *OAuthHandler) Login(c *gin.Context) {
	provider := oauthSvc.Provider(c.Param("provider"))
	state := uuid.New().String()
	url, err := h.oauthSvc.AuthCodeURL(provider, state)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeOAuthNotConfigured, nil)
		return
	}
	utils.SetOAuthStateCookie(c, "oauth_state_"+string(provider), state, h.cookiePath, h.cookieSecure)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := oauthSvc.Provider(c.Param("provider"))
	state := c.Query("state")
	code := c.Query("code")
	if code == "" {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	cookieName := "oauth_state_" + string(provider)
	savedState, err := c.Cookie(cookieName)
	if err != nil || savedState != state {
		response.FailCode(c, http.StatusBadRequest, response.CodeOAuthStateInvalid, nil)
		return
	}
	utils.ClearOAuthStateCookie(c, cookieName, h.cookiePath, h.cookieSecure)

	identity, err := h.oauthSvc.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeOAuthExchangeFail, nil)
		return
	}
	userID, err := h.oauthSvc.FindOrCreateUserForIdentity(c.Request.Context(), identity)
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeOAuthUserFail, nil)
		return
	}

	res, err := h.authSvc.StartSession(c.Request.Context(), userID, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	}, "")
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, c, "oauth", userID.String(), nil, c.ClientIP(), c.Request.UserAgent())

	redirectURL := h.frontendBase + "/auth/oauth/callback"
	redirectURL += "?access_token=" + res.AccessToken
	redirectURL += "&refresh_token=" + res.RefreshToken
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}
