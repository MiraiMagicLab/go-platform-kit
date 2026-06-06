package controllers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type RBACHandler struct {
	rbac  *services.RBACService
	admin *services.UserAdminService
	audit *services.AuditService
}

func NewRBACHandler(rbac *services.RBACService, admin *services.UserAdminService, audit *services.AuditService) *RBACHandler {
	return &RBACHandler{rbac: rbac, admin: admin, audit: audit}
}

type createRoleReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req createRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	id, err := h.rbac.CreateRole(c.Request.Context(), req.Name)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACCreateRoleFailed, nil)
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
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	id, err := h.rbac.CreatePermission(c.Request.Context(), req.Name)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACCreatePermissionFailed, nil)
		return
	}
	response.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type assignRolePermsReq struct {
	PermissionIDs []string `json:"permission_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignPermissionsToRole(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req assignRolePermsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var pids []uuid.UUID
	for _, s := range req.PermissionIDs {
		pid, err := uuid.Parse(s)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		pids = append(pids, pid)
	}
	if err := h.rbac.AssignPermissionsToRole(c.Request.Context(), roleID, pids); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type assignUserRolesReq struct {
	RoleIDs []string `json:"role_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignRolesToUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req assignUserRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var rids []uuid.UUID
	for _, s := range req.RoleIDs {
		rid, err := uuid.Parse(s)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		rids = append(rids, rid)
	}
	if err := h.rbac.AssignRolesToUser(c.Request.Context(), userID, rids); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type banUserReq struct {
	BannedUntil string `json:"banned_until" binding:"required"` // RFC3339
	Reason      string `json:"reason"`
}

func (h *RBACHandler) BanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	var req banUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	until, err := time.Parse(time.RFC3339, req.BannedUntil)
	if err != nil || !until.After(time.Now()) {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		}
		return
	}
	if h.admin == nil || h.admin.BanUser(c.Request.Context(), userID, until.UTC(), req.Reason) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"banned_until": req.BannedUntil})
		}
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true, "banned_until": until.UTC().Format(time.RFC3339)}, nil)
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"banned_until": until.UTC().Format(time.RFC3339), "reason": req.Reason})
	}
}

func (h *RBACHandler) UnbanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if h.admin == nil || h.admin.UnbanUser(c.Request.Context(), userID) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed, nil)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_unban", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		}
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.user_unban", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	}
}
func (h *RBACHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	filter := postgres.ListUsersFilter{
		Search:    c.Query("search"),
		Email:     c.Query("email"),
		SortBy:    c.DefaultQuery("sort_by", "created_at"),
		SortOrder: c.DefaultQuery("sort_order", "desc"),
	}
	if v := strings.TrimSpace(c.Query("email_verified")); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		filter.EmailVerified = &parsed
	}
	if v := strings.TrimSpace(c.Query("password_login_enabled")); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		filter.PasswordLoginEnabled = &parsed
	}
	if v := strings.TrimSpace(c.Query("is_banned")); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		filter.IsBanned = &parsed
	}
	if v := strings.TrimSpace(c.Query("created_from")); v != "" {
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		filter.CreatedFrom = &parsed
	}
	if v := strings.TrimSpace(c.Query("created_to")); v != "" {
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
			return
		}
		filter.CreatedTo = &parsed
	}

	users, total, err := h.admin.ListUsers(c.Request.Context(), page, pageSize, filter)
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}

	var list []gin.H
	for _, u := range users {
		list = append(list, gin.H{
			"id":                     u.ID.String(),
			"email":                  u.Email,
			"email_verified":         u.EmailVerified,
			"password_login_enabled": u.PasswordLoginEnabled,
			"banned_until":           u.BannedUntil,
			"ban_reason":             u.BanReason,
			"created_at":             u.CreatedAt,
			"updated_at":             u.UpdatedAt,
		})
	}

	response.Pagination(c, http.StatusOK, list, pageSize, (page-1)*pageSize, int64(total))
}

func (h *RBACHandler) DeleteUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if h.admin == nil || h.admin.DeleteUser(c.Request.Context(), userID) != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_delete", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		}
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.user_delete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	}
}
