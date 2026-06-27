package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
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

// UserAuthCache caches user auth state for JWT middleware.
type UserAuthCache interface {
	Get(ctx context.Context, userID uuid.UUID) (domain.User, bool, error)
	Set(ctx context.Context, user domain.User) error
}

// JWTAuth returns middleware that validates JWT access tokens.
func JWTAuth(jwtm *jwt.Manager, users ports.UserRepository, denylist ports.AccessTokenDenylist, userCache UserAuthCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if h == "" || !strings.HasPrefix(h, "Bearer ") {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			c.Abort()
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")

		claims, err := jwtm.ParseAccess(raw)
		if err != nil {
			if jwt.IsExpired(err) {
				httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthTokenExpired, nil)
			} else {
				httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			}
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}

		if denylist != nil {
			if denied, _ := denylist.IsDenied(c.Request.Context(), claims.ID); denied {
				httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthTokenRevoked, nil)
				c.Abort()
				return
			}
		}

		u, err := loadUserForAuth(c.Request.Context(), users, userCache, userID)
		if err != nil || u.TokenVersion != claims.TokenVersion {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthTokenRevoked, nil)
			c.Abort()
			return
		}
		if u.IsBanned() {
			httpx.Fail(c, http.StatusForbidden, httpx.CodeAuthUserBanned, map[string]interface{}{
				"banned_until": u.BannedUntil.UTC().Format("2006-01-02T15:04:05Z"),
			})
			c.Abort()
			return
		}
		if u.IsLocked() {
			httpx.Fail(c, http.StatusForbidden, httpx.CodeAuthAccountLocked, map[string]interface{}{
				"locked_until": u.LockedUntil.UTC().Format("2006-01-02T15:04:05Z"),
			})
			c.Abort()
			return
		}
		if u.IsDeleted() {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
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
