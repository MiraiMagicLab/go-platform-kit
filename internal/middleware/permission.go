package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
)

func RequirePermission(rbac *services.RBACService, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
			c.Abort()
			return
		}

		perms, err := rbac.ListUserPermissions(c.Request.Context(), userID)
		if err != nil {
			response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal)
			c.Abort()
			return
		}

		for _, p := range perms {
			if p == permission {
				c.Next()
				return
			}
		}

		response.FailCode(c, http.StatusForbidden, response.CodeAuthForbidden, permission)
		c.Abort()
	}
}
