package handler

import (
	"fmt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/admin"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/audit"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// RBACHandler handles RBAC admin endpoints.
type RBACHandler struct {
	rbacSvc  *rbac.RBACService
	adminSvc *admin.UserAdminService
	auditSvc *audit.AuditService
}

// NewRBACHandler creates an RBACHandler for role, permission, and user admin endpoints.
func NewRBACHandler(rbacSvc *rbac.RBACService, adminSvc *admin.UserAdminService, auditSvc *audit.AuditService) *RBACHandler {
	return &RBACHandler{rbacSvc: rbacSvc, adminSvc: adminSvc, auditSvc: auditSvc}
}

type createRoleReq struct {
	Name string `json:"name" binding:"required"`
}

// CreateRole handles POST /rbac/roles. It creates a new role and returns its ID.
func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req createRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	id, err := h.rbacSvc.CreateRole(c.Request.Context(), req.Name)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeRBACCreateRoleFailed, nil)
		return
	}
	httpx.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type createPermissionReq struct {
	Name string `json:"name" binding:"required"`
}

// CreatePermission handles POST /rbac/permissions. It creates a new permission and returns its ID.
func (h *RBACHandler) CreatePermission(c *gin.Context) {
	var req createPermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	id, err := h.rbacSvc.CreatePermission(c.Request.Context(), req.Name)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeRBACCreatePermissionFailed, nil)
		return
	}
	httpx.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type assignPermissionsReq struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

// AssignPermissionsToRole handles PUT /rbac/roles/:id/permissions.
// It replaces the permission set for the given role.
func (h *RBACHandler) AssignPermissionsToRole(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	var req assignPermissionsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	ids := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, s := range req.PermissionIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
			return
		}
		ids = append(ids, id)
	}
	if err := h.rbacSvc.AssignPermissionsToRole(c.Request.Context(), roleID, ids); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeRBACAssignFailed, nil)
		return
	}
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type assignRolesReq struct {
	RoleIDs []string `json:"role_ids" binding:"required"`
}

// AssignRolesToUser handles PUT /rbac/users/:id/roles.
// It replaces the role set for the given user.
func (h *RBACHandler) AssignRolesToUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	var req assignRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	ids := make([]uuid.UUID, 0, len(req.RoleIDs))
	for _, s := range req.RoleIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
			return
		}
		ids = append(ids, id)
	}
	if err := h.rbacSvc.AssignRolesToUser(c.Request.Context(), userID, ids); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeRBACAssignFailed, nil)
		return
	}
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type banReq struct {
	Until  string `json:"until" binding:"required"`
	Reason string `json:"reason"`
}

// BanUser handles POST /admin/users/:id/ban. It bans the user until the specified time
// with an optional reason.
func (h *RBACHandler) BanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	var req banReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	until, err := parseTime(req.Until)
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if err := h.adminSvc.BanUser(c.Request.Context(), userID, until, req.Reason); err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.ban", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"until": req.Until, "reason": req.Reason})
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

// UnbanUser handles POST /admin/users/:id/unban. It removes the ban from the user.
func (h *RBACHandler) UnbanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if err := h.adminSvc.UnbanUser(c.Request.Context(), userID); err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.unban", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

// DeleteUser handles DELETE /admin/users/:id. It soft-deletes the specified user.
func (h *RBACHandler) DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if err := h.adminSvc.DeleteUser(c.Request.Context(), userID); err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.delete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

// ListUsers handles GET /admin/users. It returns a paginated list of users
// with optional filters for search, email, verification status, ban status, and sorting.
func (h *RBACHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))

	filter := ports.ListUsersFilter{
		Search:    c.Query("search"),
		Email:     c.Query("email"),
		SortBy:    c.Query("sort_by"),
		SortOrder: c.Query("sort_order"),
	}
	if v := c.Query("email_verified"); v != "" {
		b := v == "true" || v == "1"
		filter.EmailVerified = &b
	}
	if v := c.Query("password_login_enabled"); v != "" {
		b := v == "true" || v == "1"
		filter.PasswordLoginEnabled = &b
	}
	if v := c.Query("is_banned"); v != "" {
		b := v == "true" || v == "1"
		filter.IsBanned = &b
	}

	users, total, err := h.adminSvc.ListUsers(c.Request.Context(), page, pageSize, filter)
	if err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeInternal, nil)
		return
	}

	type userView struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, userView{
			ID:        u.ID.String(),
			Email:     u.Email,
			CreatedAt: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			UpdatedAt: u.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	httpx.Pagination(c, http.StatusOK, out, page, pageSize, int64(total))
}

func parseTime(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time format: %s", s)
}
