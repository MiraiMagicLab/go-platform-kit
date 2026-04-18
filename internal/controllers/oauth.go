package controllers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type OAuthHandler struct {
	oauth     *services.OAuthService
	auth      *services.AuthService
	lifecycle *AuthLifecycle
}

func NewOAuthHandler(oauth *services.OAuthService, auth *services.AuthService, publicBaseURL string, lifecycle *AuthLifecycle) *OAuthHandler {
	_ = publicBaseURL
	return &OAuthHandler{oauth: oauth, auth: auth, lifecycle: lifecycle}
}

func (h *OAuthHandler) Login(c *gin.Context) {
	provider := services.OAuthProvider(strings.ToLower(c.Param("provider")))
	state := randomHex(16)
	c.SetCookie("oauth_state", state, 300, "/", "", false, true)

	url, err := h.oauth.AuthCodeURL(provider, state)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthNotConfigured, nil)
		return
	}
	c.Redirect(http.StatusFound, url)
}

func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := services.OAuthProvider(strings.ToLower(c.Param("provider")))
	code := c.Query("code")
	state := c.Query("state")
	stored, err := c.Cookie("oauth_state")
	if err != nil || stored == "" || stored != state {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthStateInvalid, nil)
		return
	}
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	id, err := h.oauth.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthExchangeFail, nil)
		return
	}
	userID, err := h.oauth.FindOrCreateUserForIdentity(c.Request.Context(), id)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthUserFail, nil)
		return
	}

	session, err := h.auth.StartSession(c.Request.Context(), userID, services.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	})
	if err != nil {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}

	fireAfterSessionIssued(h.lifecycle, "oauth", userID, nil, c.ClientIP(), c.Request.UserAgent())
	// For service-to-service usage, return JSON. You can also redirect to a frontend and pass tokens another way.
	response.Success(c, http.StatusOK, "success", session, nil)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
