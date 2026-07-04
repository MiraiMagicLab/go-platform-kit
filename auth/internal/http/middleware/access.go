package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// RequireAnyPermission returns middleware that passes when the user has any listed permission.
func RequireAnyPermission(rbacSvc *rbac.RBACService, adminBypass bool, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusUnauthorized, apperrors.CodeUnauthorized, nil)
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
			httpx.FailCode(c, http.StatusInternalServerError, apperrors.CodeInternal, nil)
			c.Abort()
			return
		}
		permSet := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			permSet[p] = struct{}{}
		}
		for _, required := range permissions {
			if _, ok := permSet[required]; ok {
				c.Next()
				return
			}
		}

		httpx.FailCode(c, http.StatusForbidden, apperrors.CodeForbidden, nil)
		c.Abort()
	}
}
