package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/rbac"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

// RequireRole returns middleware that checks if the user has at least one of the allowed roles.
func RequireRole(rbacSvc *rbac.RBACService, allowed ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		roles, err := rbacSvc.ListUserRoles(c.Request.Context(), userID)
		if err != nil {
			response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
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

		response.FailCode(c, http.StatusForbidden, response.CodeAuthForbidden, nil)
		c.Abort()
	}
}
