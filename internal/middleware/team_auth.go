package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

const teamAuthCtxKey = "team_auth"

// TeamAuth is operator context from control-plane TeamToken.
type TeamAuth struct {
	ActorUserID  uuid.UUID
	WorkspaceID  uuid.UUID
	AppID        uuid.UUID
	AppAccess    string
	Capabilities []string
}

func setTeamAuth(c *gin.Context, ta TeamAuth) {
	c.Set(teamAuthCtxKey, ta)
}

// TeamAuthFromCtx returns TeamAuth populated by TeamTokenMiddleware.
func TeamAuthFromCtx(c *gin.Context) (TeamAuth, bool) {
	v, ok := c.Get(teamAuthCtxKey)
	if !ok {
		return TeamAuth{}, false
	}
	ta, ok := v.(TeamAuth)
	return ta, ok
}

// RequireTeamAccess gates admin routes by app_access claim (read|write).
func RequireTeamAccess(level string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ta, ok := TeamAuthFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}
		switch level {
		case "read":
			if ta.AppAccess == "read" || ta.AppAccess == "write" {
				c.Next()
				return
			}
		case "write":
			if ta.AppAccess == "write" {
				c.Next()
				return
			}
		}
		response.FailCode(c, http.StatusForbidden, response.CodeAuthForbidden, nil)
		c.Abort()
	}
}

// RequireTeamCapability gates admin routes by capabilities claim.
func RequireTeamCapability(capability string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ta, ok := TeamAuthFromCtx(c)
		if !ok {
			response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}
		for _, cap := range ta.Capabilities {
			if cap == capability {
				c.Next()
				return
			}
		}
		response.FailCodeArgs(c, http.StatusForbidden, response.CodeAuthForbidden, capability)
		c.Abort()
	}
}
