package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

func RequirePermission(rbac *services.RBACService, permission string, adminBypass bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		if adminBypass {
			roles, err := rbac.ListUserRoles(c.Request.Context(), userID)
			if err == nil {
				for _, r := range roles {
					if r == "admin" {
						c.Next()
						return
					}
				}
			}
		}

		perms, err := rbac.ListUserPermissions(c.Request.Context(), userID)
		if err != nil {
			response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
			c.Abort()
			return
		}

		for _, p := range perms {
			if p == permission {
				c.Next()
				return
			}
		}

		response.FailCodeArgs(c, http.StatusForbidden, response.CodeAuthForbidden, permission)
		c.Abort()
	}
}
