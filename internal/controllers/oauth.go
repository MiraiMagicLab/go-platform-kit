package controllers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/internal/utils"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type OAuthHandler struct {
	oauth           *services.OAuthService
	auth            *services.AuthService
	lifecycle       *AuthLifecycle
	frontendBaseURL string
	authPath        string
	secure          bool
}

func NewOAuthHandler(
	oauth *services.OAuthService,
	auth *services.AuthService,
	authPath string,
	frontendBaseURL string,
	secure bool,
	lifecycle *AuthLifecycle,
) *OAuthHandler {
	return &OAuthHandler{
		oauth:           oauth,
		auth:            auth,
		lifecycle:       lifecycle,
		frontendBaseURL: frontendBaseURL,
		authPath:        authPath,
		secure:          secure,
	}
}

func (h *OAuthHandler) Login(c *gin.Context) {
	provider := services.OAuthProvider(strings.ToLower(c.Param("provider")))
	state := randomHex(16)
	utils.SetOAuthStateCookie(c, "oauth_state", state, h.authPath, h.secure)

	authURL, err := h.oauth.AuthCodeURL(provider, state)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeOAuthNotConfigured)
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthNotConfigured, nil)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := services.OAuthProvider(strings.ToLower(c.Param("provider")))
	code := c.Query("code")
	state := c.Query("state")
	stored, err := c.Cookie("oauth_state")
	if err != nil || stored == "" || stored != state {
		middleware.SetAuthErrorCode(c, response.CodeOAuthStateInvalid)
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthStateInvalid, nil)
		return
	}
	utils.ClearOAuthStateCookie(c, "oauth_state", "/", h.secure)

	id, err := h.oauth.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeOAuthExchangeFail)
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthExchangeFail, nil)
		return
	}
	userID, err := h.oauth.FindOrCreateUserForIdentity(c.Request.Context(), id)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeOAuthUserFail)
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthUserFail, nil)
		return
	}

	ua := c.Request.UserAgent()
	deviceName := utils.DeviceNameFromUA(ua)

	session, err := h.auth.StartSession(c.Request.Context(), userID, services.ClientMeta{
		IP: c.ClientIP(),
		UA: ua,
	}, deviceName)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, "oauth", userID, nil, c.ClientIP(), ua)

	if h.frontendBaseURL != "" {
		redirectURL := fmt.Sprintf("%s/auth/oauth/callback?access_token=%s&refresh_token=%s",
			strings.TrimSuffix(h.frontendBaseURL, "/"),
			url.QueryEscape(session.AccessToken),
			url.QueryEscape(session.RefreshToken),
		)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	response.Success(c, http.StatusOK, "success", session, nil)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
