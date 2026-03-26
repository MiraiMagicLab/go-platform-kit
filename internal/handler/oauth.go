package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/service"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "oauth not configured"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	id, err := h.oauth.ExchangeAndFetchIdentity(c.Request.Context(), provider, code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "oauth exchange failed"})
		return
	}
	userID, err := h.oauth.FindOrCreateUserForIdentity(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "oauth user create failed"})
		return
	}

	session, err := h.auth.StartSession(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "could not create session"})
		return
	}

	// For service-to-service usage, return JSON. You can also redirect to a frontend and pass tokens another way.
	c.JSON(http.StatusOK, session)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
