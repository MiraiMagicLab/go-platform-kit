package controllers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
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
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid request body", nil)
		return
	}
	id, err := h.rbac.CreateRole(c.Request.Context(), req.Name)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACCreateRoleFailed, "Could not create role", nil)
		return
	}
	response.Success(c, http.StatusCreated, "Role created", gin.H{"id": id.String()})
}

type createPermissionReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreatePermission(c *gin.Context) {
	var req createPermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid request body", nil)
		return
	}
	id, err := h.rbac.CreatePermission(c.Request.Context(), req.Name)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACCreatePermissionFailed, "Could not create permission", nil)
		return
	}
	response.Success(c, http.StatusCreated, "Permission created", gin.H{"id": id.String()})
}

type assignRolePermsReq struct {
	PermissionIDs []string `json:"permission_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignPermissionsToRole(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid role id", nil)
		return
	}
	var req assignRolePermsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid request body", nil)
		return
	}
	var pids []uuid.UUID
	for _, s := range req.PermissionIDs {
		pid, err := uuid.Parse(s)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid permission id", nil)
			return
		}
		pids = append(pids, pid)
	}
	if err := h.rbac.AssignPermissionsToRole(c.Request.Context(), roleID, pids); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACAssignFailed, "Could not assign permissions", nil)
		return
	}
	response.Success(c, http.StatusOK, "Permissions assigned", gin.H{"ok": true})
}

type assignUserRolesReq struct {
	RoleIDs []string `json:"role_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignRolesToUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid user id", nil)
		return
	}
	var req assignUserRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid request body", nil)
		return
	}
	var rids []uuid.UUID
	for _, s := range req.RoleIDs {
		rid, err := uuid.Parse(s)
		if err != nil {
			response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid role id", nil)
			return
		}
		rids = append(rids, rid)
	}
	if err := h.rbac.AssignRolesToUser(c.Request.Context(), userID, rids); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeRBACAssignFailed, "Could not assign roles", nil)
		return
	}
	response.Success(c, http.StatusOK, "Roles assigned", gin.H{"ok": true})
}

type banUserReq struct {
	BannedUntil string `json:"banned_until" binding:"required"` // RFC3339
	Reason      string `json:"reason"`
}

func (h *RBACHandler) BanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	var req banUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	until, err := time.Parse(time.RFC3339, req.BannedUntil)
	if err != nil || !until.After(time.Now()) {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		}
		return
	}
	if h.admin == nil || h.admin.BanUser(c.Request.Context(), userID, until.UTC(), req.Reason) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"banned_until": req.BannedUntil})
		}
		return
	}
	response.Success(c, http.StatusOK, "User banned", gin.H{"ok": true, "banned_until": until.UTC().Format(time.RFC3339)})
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.user_ban", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"banned_until": until.UTC().Format(time.RFC3339), "reason": req.Reason})
	}
}

func (h *RBACHandler) UnbanUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	if h.admin == nil || h.admin.UnbanUser(c.Request.Context(), userID) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeRBACAssignFailed)
		if h.audit != nil {
			h.audit.Log(c.Request.Context(), &userID, "auth.user_unban", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		}
		return
	}
	response.Success(c, http.StatusOK, "User unbanned", gin.H{"ok": true})
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.user_unban", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	}
}
