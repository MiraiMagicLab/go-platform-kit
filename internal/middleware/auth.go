package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repository/postgres"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/token"
)

const (
	ctxUserIDKey    = "user_id"
	ctxAccessJTIKey = "access_jti"
	ctxAccessExpKey = "access_exp"
)

func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(ctxUserIDKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

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

type AccessTokenDenylistChecker interface {
	IsDenied(ctx *gin.Context, jti string) (bool, error)
}

type denylistAdapter struct {
	check func(ctx *gin.Context, jti string) (bool, error)
}

func (d denylistAdapter) IsDenied(ctx *gin.Context, jti string) (bool, error) {
	if d.check == nil {
		return false, nil
	}
	return d.check(ctx, jti)
}

func JWTAuth(jwtm *token.JWTManager, users *postgres.UserRepo, denylistFn func(ctx *gin.Context, jti string) (bool, error)) gin.HandlerFunc {
	denylist := denylistAdapter{check: denylistFn}
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if h == "" || !strings.HasPrefix(h, "Bearer ") {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
			c.Abort()
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")

		claims, err := jwtm.ParseAccess(raw)
		if err != nil {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidToken)
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidToken)
			c.Abort()
			return
		}

		if denied, _ := denylist.IsDenied(c, claims.ID); denied {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthTokenRevoked)
			c.Abort()
			return
		}

		// Enforce token_version to support immediate logout invalidation.
		u, err := users.GetByID(c.Request.Context(), userID)
		if err != nil || u.TokenVersion != claims.TokenVersion {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthTokenRevoked)
			c.Abort()
			return
		}
		if u.BannedUntil != nil && time.Now().Before(*u.BannedUntil) {
			response.Fail(c, http.StatusForbidden, response.CodeAuthUserBanned, response.DefaultMessage(response.CodeAuthUserBanned), map[string]interface{}{
				"banned_until": u.BannedUntil.UTC().Format("2006-01-02T15:04:05Z"),
			})
			c.Abort()
			return
		}

		c.Set(ctxUserIDKey, userID)
		c.Set(ctxAccessJTIKey, claims.ID)
		if claims.ExpiresAt != nil {
			c.Set(ctxAccessExpKey, claims.ExpiresAt.Time)
		}
		c.Next()
	}
}
