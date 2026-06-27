package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin/middleware"
)

// TeamAuth is operator context from a control-plane TeamToken.
type TeamAuth struct {
	ActorUserID  uuid.UUID
	WorkspaceID  uuid.UUID
	AppID        uuid.UUID
	AppAccess    string
	Capabilities []string
}

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

func (m *Module) RequireTeamAccess(level string) gin.HandlerFunc {
	return httpmw.RequireTeamAccess(level)
}

func (m *Module) RequireTeamCapability(capability string) gin.HandlerFunc {
	return httpmw.RequireTeamCapability(capability)
}

func (m *Module) RequireRole(roles ...string) gin.HandlerFunc {
	return httpmw.RequireRole(m.rbacSvc, roles...)
}
