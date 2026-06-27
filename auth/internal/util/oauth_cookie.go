package util

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// OAuthCookieMaxAge is the lifetime in seconds of the OAuth CSRF state cookie.
	OAuthCookieMaxAge = 300 // 5 minutes
)

// SetOAuthStateCookie sets the OAuth CSRF state cookie with hardened security attributes.
// path should be the auth mount prefix (e.g. "/auth").
// Set secure=true in production (HTTPS).
func SetOAuthStateCookie(c *gin.Context, name, value, path string, secure bool) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, OAuthCookieMaxAge, path, "", secure, true)
}

// ClearOAuthStateCookie removes the OAuth state cookie.
func ClearOAuthStateCookie(c *gin.Context, name, path string, secure bool) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, "", -1, path, "", secure, true)
}
