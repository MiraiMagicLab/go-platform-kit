package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
	"github.com/MiraiMagicLab/go-auth-lib/internal/service"
)

type OAuthHandler struct {
	oauth *service.OAuthService
	auth  *service.AuthService
}

func NewOAuthHandler(oauth *service.OAuthService, auth *service.AuthService, publicBaseURL string) *OAuthHandler {
	_ = publicBaseURL
	return &OAuthHandler{oauth: oauth, auth: auth}
}

func (h *OAuthHandler) Login(c *gin.Context) {
	provider := service.OAuthProvider(strings.ToLower(c.Param("provider")))
	state := randomHex(16)
	c.SetCookie("oauth_state", state, 300, "/", "", false, true)

	url, err := h.oauth.AuthCodeURL(provider, state)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthNotConfigured, "OAuth provider is not configured", nil)
		return
	}
	c.Redirect(http.StatusFound, url)
}

func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := service.OAuthProvider(strings.ToLower(c.Param("provider")))
	code := c.Query("code")
	state := c.Query("state")
	stored, err := c.Cookie("oauth_state")
	if err != nil || stored == "" || stored != state {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthStateInvalid, "Invalid OAuth state", nil)
		return
	}
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	id, err := h.oauth.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthExchangeFail, "OAuth exchange failed", nil)
		return
	}
	userID, err := h.oauth.FindOrCreateUserForIdentity(c.Request.Context(), id)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeOAuthUserFail, "OAuth user processing failed", nil)
		return
	}

	session, err := h.auth.StartSession(c.Request.Context(), userID)
	if err != nil {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, "Could not create session", nil)
		return
	}

	// For service-to-service usage, return JSON. You can also redirect to a frontend and pass tokens another way.
	response.Success(c, http.StatusOK, "OAuth login success", session)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
