package http

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/admin"
	"github.com/MiraiMagicLab/go-auth-lib/internal/audit"
	"github.com/MiraiMagicLab/go-auth-lib/internal/rbac"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/ports"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

// RBACHandler handles RBAC admin endpoints.
type RBACHandler struct {
	rbacSvc  *rbac.RBACService
	adminSvc *admin.UserAdminService
	auditSvc *audit.AuditService
}

func NewRBACHandler(rbacSvc *rbac.RBACService, adminSvc *admin.UserAdminService, auditSvc *audit.AuditService) *RBACHandler {
	return &RBACHandler{rbacSvc: rbacSvc, adminSvc: adminSvc, auditSvc: auditSvc}
}

type createRoleReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req createRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	id, err := h.rbacSvc.CreateRole(c.Request.Context(), req.Name)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACCreateRoleFailed, nil)
		return
	}
	response.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type createPermissionReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreatePermission(c *gin.Context) {
	var req createPermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	id, err := h.rbacSvc.CreatePermission(c.Request.Context(), req.Name)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACCreatePermissionFailed, nil)
		return
	}
	response.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type assignPermissionsReq struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

func (h *RBACHandler) AssignPermissionsToRole(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req assignPermissionsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	ids := make([]uuid.UUID, 0, len(req.PermissionIDs))
	for _, s := range req.PermissionIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		ids = append(ids, id)
	}
	if err := h.rbacSvc.AssignPermissionsToRole(c.Request.Context(), roleID, ids); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type assignRolesReq struct {
	RoleIDs []string `json:"role_ids" binding:"required"`
}

func (h *RBACHandler) AssignRolesToUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req assignRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	ids := make([]uuid.UUID, 0, len(req.RoleIDs))
	for _, s := range req.RoleIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		ids = append(ids, id)
	}
	if err := h.rbacSvc.AssignRolesToUser(c.Request.Context(), userID, ids); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type banReq struct {
	Until  string `json:"until" binding:"required"`
	Reason string `json:"reason"`
}

func (h *RBACHandler) BanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req banReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	until, err := parseTime(req.Until)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if err := h.adminSvc.BanUser(c.Request.Context(), userID, until, req.Reason); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.ban", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"until": req.Until, "reason": req.Reason})
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

func (h *RBACHandler) UnbanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if err := h.adminSvc.UnbanUser(c.Request.Context(), userID); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.unban", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

func (h *RBACHandler) DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if err := h.adminSvc.DeleteUser(c.Request.Context(), userID); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "user.delete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

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
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
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

	response.Pagination(c, http.StatusOK, out, page, pageSize, int64(total))
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

// Required imports are in the import block above.
