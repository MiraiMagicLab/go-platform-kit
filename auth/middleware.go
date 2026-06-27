package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"time"

	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
)

// TeamAuth is operator context extracted from a control-plane TeamToken.
type TeamAuth struct {
	ActorUserID  uuid.UUID
	WorkspaceID  uuid.UUID
	AppID        uuid.UUID
	AppAccess    string
	Capabilities []string
}

// TeamAuthFromCtx returns TeamAuth when the request was authenticated via TeamToken middleware.
func TeamAuthFromCtx(c *gin.Context) (TeamAuth, bool) {
	m, ok := httpmw.TeamAuthFromCtx(c)
	if !ok {
		return TeamAuth{}, false
	}
	return TeamAuth{
		ActorUserID:  m.ActorUserID,
		WorkspaceID:  m.WorkspaceID,
		AppID:        m.AppID,
		AppAccess:    m.AppAccess,
		Capabilities: m.Capabilities,
	}, true
}

// RequireTeamAccess returns middleware that enforces a minimum team access level.
func (m *Module) RequireTeamAccess(level string) gin.HandlerFunc {
	return httpmw.RequireTeamAccess(level)
}

// RequireTeamCapability returns middleware that requires a control-plane capability.
func (m *Module) RequireTeamCapability(capability string) gin.HandlerFunc {
	return httpmw.RequireTeamCapability(capability)
}

// RequireRole returns middleware that requires the user to hold at least one of the given roles.
func (m *Module) RequireRole(roles ...string) gin.HandlerFunc {
	return httpmw.RequireRole(m.rbacSvc, roles...)
}

// TeamTokenMiddleware validates control-plane TeamTokens for operator routes.
func (m *Module) TeamTokenMiddleware() gin.HandlerFunc { return m.teamTokenMW }

// UserIDFromCtx returns the authenticated user ID set by [Module.AuthMiddleware].
func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) { return httpmw.UserIDFromCtx(c) }

// SessionIDFromCtx returns the session ID from the access token claims.
func SessionIDFromCtx(c *gin.Context) uuid.UUID { return httpmw.SessionIDFromCtx(c) }

// AccessTokenMetaFromCtx returns JTI and expiry from the validated access token.
func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	return httpmw.AccessTokenMetaFromCtx(c)
}
