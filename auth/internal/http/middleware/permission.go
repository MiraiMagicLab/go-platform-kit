package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// RequirePermission returns middleware that checks if the user has the named permission.
// If adminBypass is true and the user has the "admin" role, the check is skipped.
func RequirePermission(rbacSvc *rbac.RBACService, permission string, adminBypass bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			c.Abort()
			return
		}

		if adminBypass {
			roles, _ := rbacSvc.ListUserRoles(c.Request.Context(), userID)
			for _, r := range roles {
				if r == "admin" {
					c.Next()
					return
				}
			}
		}

		perms, err := rbacSvc.ListUserPermissions(c.Request.Context(), userID)
		if err != nil {
			httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
			c.Abort()
			return
		}
		for _, p := range perms {
			if p == permission {
				c.Next()
				return
			}
		}

		httpx.FailCodeArgs(c, http.StatusForbidden, httpx.CodeForbidden, permission)
		c.Abort()
	}
}
