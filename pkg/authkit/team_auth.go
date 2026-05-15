package authkit

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
)

// TeamAuth is operator context from a control-plane TeamToken (after TeamTokenMiddleware).
type TeamAuth struct {
	ActorUserID  uuid.UUID
	WorkspaceID  uuid.UUID
	AppID        uuid.UUID
	AppAccess    string // "read" | "write"
	Capabilities []string
}

// TeamAuthFromCtx returns TeamAuth set by TeamTokenMiddleware.
func TeamAuthFromCtx(c *gin.Context) (TeamAuth, bool) {
	m, ok := middleware.TeamAuthFromCtx(c)
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

// RequireTeamAccess enforces TeamToken app_access (read or write).
func (m *Module) RequireTeamAccess(level string) gin.HandlerFunc {
	return middleware.RequireTeamAccess(level)
}

// RequireTeamCapability enforces a capability from TeamToken claims.
func (m *Module) RequireTeamCapability(capability string) gin.HandlerFunc {
	return middleware.RequireTeamCapability(capability)
}

// RequireRole enforces end-user roles from app DB (use with AuthMiddleware, not TeamToken).
func (m *Module) RequireRole(roles ...string) gin.HandlerFunc {
	return middleware.RequireRole(m.rbacSvc, roles...)
}
