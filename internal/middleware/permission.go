package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/service"
)

func RequirePermission(rbac *service.RBACService, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := UserIDFromCtx(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		perms, err := rbac.ListUserPermissions(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to load permissions"})
			return
		}

		for _, p := range perms {
			if p == permission {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}
