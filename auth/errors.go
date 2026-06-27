package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// MapError translates auth domain errors into stable HTTP error codes.
func MapError(err error) (httpx.MappedError, bool) {
	if err == nil {
		return httpx.MappedError{}, false
	}
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return httpx.MappedError{Status: http.StatusUnauthorized, Code: httpx.CodeAuthInvalidCredentials}, true
	case errors.Is(err, domain.ErrInvalidRefresh):
		return httpx.MappedError{Status: http.StatusUnauthorized, Code: httpx.CodeAuthInvalidRefresh}, true
	case errors.Is(err, domain.ErrSessionNotFound):
		return httpx.MappedError{Status: http.StatusNotFound, Code: httpx.CodeSessionNotFound}, true
	}
	var locked domain.ErrAccountLocked
	if errors.As(err, &locked) {
		params := map[string]any{}
		if locked.Until != nil {
			params["locked_until"] = locked.Until.UTC().Format(time.RFC3339)
		}
		return httpx.MappedError{Status: http.StatusLocked, Code: httpx.CodeAuthAccountLocked, Params: params}, true
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
		return httpx.MappedError{Status: http.StatusForbidden, Code: httpx.CodeAuthUserBanned, Params: params}, true
	}
	var notVerified domain.ErrEmailNotVerified
	if errors.As(err, &notVerified) {
		return httpx.MappedError{Status: http.StatusForbidden, Code: httpx.CodeAuthEmailNotVerified}, true
	}
	return httpx.MappedError{}, false
}

// WriteError writes a mapped auth error or a fallback response. Returns true when written.
func WriteError(c *gin.Context, err error, fallbackCode string, fallbackStatus int) bool {
	return httpx.WriteError(c, err, fallbackCode, fallbackStatus, MapError)
}
