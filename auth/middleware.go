package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"time"

	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
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

// JWTAuth validates JWT access tokens for host application routes.
func (a *Auth) JWTAuth() gin.HandlerFunc {
	if a == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return a.authMW
}

// AuthMiddleware is an alias for [Auth.JWTAuth].
func (a *Auth) AuthMiddleware() gin.HandlerFunc { return a.JWTAuth() }

// RequirePermission returns middleware that checks a single RBAC permission.
func (a *Auth) RequirePermission(permission string) gin.HandlerFunc {
	if a == nil || a.rbacSvc == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return httpmw.RequirePermission(a.rbacSvc, permission, a.cfg.AdminBypassPermission)
}

// RequirePermissionNoBypass returns middleware that checks a permission without admin bypass.
func (a *Auth) RequirePermissionNoBypass(permission string) gin.HandlerFunc {
	if a == nil || a.rbacSvc == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return httpmw.RequirePermission(a.rbacSvc, permission, false)
}

// RequireRBACAdmin returns middleware that requires the configured RBAC admin permission.
func (a *Auth) RequireRBACAdmin() gin.HandlerFunc {
	if a == nil || a.rbacSvc == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return httpmw.RequirePermission(a.rbacSvc, a.cfg.RBACAdminPermission, a.cfg.AdminBypassPermission)
}

// RequireTeamAccess returns middleware that enforces a minimum team access level.
func (a *Auth) RequireTeamAccess(level string) gin.HandlerFunc {
	return httpmw.RequireTeamAccess(level)
}

// RequireTeamCapability returns middleware that requires a control-plane capability.
func (a *Auth) RequireTeamCapability(capability string) gin.HandlerFunc {
	return httpmw.RequireTeamCapability(capability)
}

// RequireRole returns middleware that requires the user to hold at least one of the given roles.
func (a *Auth) RequireRole(roles ...string) gin.HandlerFunc {
	if a == nil || a.rbacSvc == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return httpmw.RequireRole(a.rbacSvc, roles...)
}

// RequireAccess returns authorization middleware based on [Config.AuthZ].Mode.
//
//   - AuthZNone: pass-through (no check)
//   - AuthZRole: checks any of the given role names
//   - AuthZRbac: checks any of the given permission names
//
// Prefer this over calling [Auth.RequirePermission] or [Auth.RequireRole] directly
// when the host app configures AuthZ mode via config.
func (a *Auth) RequireAccess(values ...string) gin.HandlerFunc {
	if a == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	switch a.cfg.AuthZ.Mode {
	case AuthZNone:
		return func(c *gin.Context) { c.Next() }
	case AuthZRole:
		return a.RequireRole(values...)
	case AuthZRbac:
		if len(values) == 0 {
			return func(c *gin.Context) {
				httpx.FailCode(c, http.StatusForbidden, apperrors.CodeForbidden, nil)
				c.Abort()
			}
		}
		if len(values) == 1 {
			return a.RequirePermission(values[0])
		}
		if a.rbacSvc == nil {
			return func(c *gin.Context) { c.Abort() }
		}
		return httpmw.RequireAnyPermission(a.rbacSvc, a.cfg.AdminBypassPermission, values...)
	default:
		return func(c *gin.Context) { c.Abort() }
	}
}

// TeamTokenMiddleware validates control-plane TeamTokens for operator routes.
func (a *Auth) TeamTokenMiddleware() gin.HandlerFunc {
	if a == nil {
		return func(c *gin.Context) { c.Abort() }
	}
	return a.teamTokenMW
}

// UserIDFromCtx returns the authenticated user ID set by [Auth.JWTAuth].
func UserIDFromCtx(c *gin.Context) (uuid.UUID, bool) { return httpmw.UserIDFromCtx(c) }

// SessionIDFromCtx returns the session ID from the access token claims.
func SessionIDFromCtx(c *gin.Context) uuid.UUID { return httpmw.SessionIDFromCtx(c) }

// AccessTokenMetaFromCtx returns JTI and expiry from the validated access token.
func AccessTokenMetaFromCtx(c *gin.Context) (string, time.Time, bool) {
	return httpmw.AccessTokenMetaFromCtx(c)
}
