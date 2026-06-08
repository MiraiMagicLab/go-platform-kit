package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/response"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/token"
)

const (
	ctxUserIDKey    = "user_id"
	ctxAccessJTIKey = "access_jti"
	ctxAccessExpKey = "access_exp"
	ctxSessionIDKey = "session_id"
	ctxErrorCodeKey = "auth_error_code"
)

// UserIDFromCtx returns the authenticated user ID from the Gin context.
func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(ctxUserIDKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// AccessTokenMetaFromCtx returns the access token JTI and expiration from the Gin context.
func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	jtiRaw, ok := c.Get(ctxAccessJTIKey)
	if !ok {
		return "", time.Time{}, false
	}
	expRaw, ok := c.Get(ctxAccessExpKey)
	if !ok {
		return "", time.Time{}, false
	}
	jti, ok1 := jtiRaw.(string)
	exp, ok2 := expRaw.(time.Time)
	if !ok1 || !ok2 {
		return "", time.Time{}, false
	}
	return jti, exp, true
}

// SessionIDFromCtx returns the session ID from the access JWT claim.
func SessionIDFromCtx(c *gin.Context) uuid.UUID {
	v, ok := c.Get(ctxSessionIDKey)
	if !ok {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// SetAuthErrorCode sets the error code in the Gin context for access logging.
func SetAuthErrorCode(c *gin.Context, code string) {
	c.Set(ctxErrorCodeKey, code)
}

// JWTAuth returns middleware that validates JWT access tokens.
func JWTAuth(jwtm *token.JWTManager, users ports.UserRepository, denylist ports.AccessTokenDenylist) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if h == "" || !strings.HasPrefix(h, "Bearer ") {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")

		claims, err := jwtm.ParseAccess(raw)
		if err != nil {
			if token.IsExpired(err) {
				response.FailCode(c, http.StatusUnauthorized, response.CodeAuthTokenExpired, nil)
			} else {
				response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidToken, nil)
			}
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidToken, nil)
			c.Abort()
			return
		}

		if denylist != nil {
			if denied, _ := denylist.IsDenied(c.Request.Context(), claims.ID); denied {
				response.FailCode(c, http.StatusUnauthorized, response.CodeAuthTokenRevoked, nil)
				c.Abort()
				return
			}
		}

		u, err := users.GetByID(c.Request.Context(), userID)
		if err != nil || u.TokenVersion != claims.TokenVersion {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthTokenRevoked, nil)
			c.Abort()
			return
		}
		if u.IsBanned() {
			response.Fail(c, http.StatusForbidden, response.CodeAuthUserBanned, map[string]interface{}{
				"banned_until": u.BannedUntil.UTC().Format("2006-01-02T15:04:05Z"),
			})
			c.Abort()
			return
		}
		if u.IsLocked() {
			response.Fail(c, http.StatusForbidden, response.CodeAuthAccountLocked, map[string]interface{}{
				"locked_until": u.LockedUntil.UTC().Format("2006-01-02T15:04:05Z"),
			})
			c.Abort()
			return
		}
		if u.IsDeleted() {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		c.Set(ctxUserIDKey, userID)
		c.Set(ctxAccessJTIKey, claims.ID)
		if claims.ExpiresAt != nil {
			c.Set(ctxAccessExpKey, claims.ExpiresAt.Time)
		}
		sid := uuid.Nil
		if claims.SessionID != "" {
			if p, err := uuid.Parse(claims.SessionID); err == nil {
				sid = p
			}
		}
		c.Set(ctxSessionIDKey, sid)
		c.Next()
	}
}
