package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// MapAuthError translates auth domain errors into stable HTTP error codes.
func MapAuthError(err error) (httpx.MappedError, bool) {
	if err == nil {
		return httpx.MappedError{}, false
	}
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return httpx.MappedError{http.StatusUnauthorized, httpx.CodeAuthInvalidCredentials, nil}, true
	case errors.Is(err, domain.ErrInvalidRefresh):
		return httpx.MappedError{http.StatusUnauthorized, httpx.CodeAuthInvalidRefresh, nil}, true
	case errors.Is(err, domain.ErrSessionNotFound):
		return httpx.MappedError{http.StatusNotFound, httpx.CodeSessionNotFound, nil}, true
	}
	var locked domain.ErrAccountLocked
	if errors.As(err, &locked) {
		params := map[string]any{}
		if locked.Until != nil {
			params["locked_until"] = locked.Until.UTC().Format(time.RFC3339)
		}
		return httpx.MappedError{http.StatusLocked, httpx.CodeAuthAccountLocked, params}, true
	}
	var banned domain.ErrUserBanned
	if errors.As(err, &banned) {
		params := map[string]any{}
		if banned.Until != nil {
			params["banned_until"] = banned.Until.UTC().Format(time.RFC3339)
		}
		if banned.Reason != nil {
			params["reason"] = *banned.Reason
		}
		return httpx.MappedError{http.StatusForbidden, httpx.CodeAuthUserBanned, params}, true
	}
	var notVerified domain.ErrEmailNotVerified
	if errors.As(err, &notVerified) {
		return httpx.MappedError{http.StatusForbidden, httpx.CodeAuthEmailNotVerified, nil}, true
	}
	return httpx.MappedError{}, false
}

// WriteAuthError writes a mapped auth error or a generic fallback response.
func WriteAuthError(c *gin.Context, err error, fallbackCode string, fallbackStatus int) bool {
	return httpx.WriteError(c, err, fallbackCode, fallbackStatus, MapAuthError)
}
