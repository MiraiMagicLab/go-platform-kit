package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

// RequireRole checks end-user roles in app DB (JWT auth, not TeamToken).
func RequireRole(rbac *services.RBACService, allowed ...string) gin.HandlerFunc {
	allowedSet := map[string]struct{}{}
	for _, r := range allowed {
		if r != "" {
			allowedSet[r] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}
		roles, err := rbac.ListUserRoles(c.Request.Context(), userID)
		if err != nil {
			response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
			c.Abort()
			return
		}
		for _, r := range roles {
			if _, ok := allowedSet[r]; ok {
				c.Next()
				return
			}
		}
		response.FailCode(c, http.StatusForbidden, response.CodeAuthForbidden, nil)
		c.Abort()
	}
}
