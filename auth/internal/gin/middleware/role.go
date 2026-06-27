package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// RequireRole returns middleware that checks if the user has at least one of the allowed roles.
func RequireRole(rbacSvc *rbac.RBACService, allowed ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			c.Abort()
			return
		}

		roles, err := rbacSvc.ListUserRoles(c.Request.Context(), userID)
		if err != nil {
			httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
			c.Abort()
			return
		}

		roleSet := make(map[string]struct{}, len(roles))
		for _, r := range roles {
			roleSet[r] = struct{}{}
		}
		for _, a := range allowed {
			if _, ok := roleSet[a]; ok {
				c.Next()
				return
			}
		}

		httpx.FailCode(c, http.StatusForbidden, httpx.CodeForbidden, nil)
		c.Abort()
	}
}
