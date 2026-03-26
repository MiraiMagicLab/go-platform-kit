package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/tienh/authsvc/internal/service"
)

type RBACHandler struct {
	rbac *service.RBACService
}

func NewRBACHandler(rbac *service.RBACService) *RBACHandler {
	return &RBACHandler{rbac: rbac}
}

type createRoleReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req createRoleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := h.rbac.CreateRole(c.Request.Context(), req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not create role"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id.String()})
}

type createPermissionReq struct {
	Name string `json:"name" binding:"required"`
}

func (h *RBACHandler) CreatePermission(c *gin.Context) {
	var req createPermissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id, err := h.rbac.CreatePermission(c.Request.Context(), req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not create permission"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id.String()})
}

type assignRolePermsReq struct {
	PermissionIDs []string `json:"permission_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignPermissionsToRole(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
		return
	}
	var req assignRolePermsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var pids []uuid.UUID
	for _, s := range req.PermissionIDs {
		pid, err := uuid.Parse(s)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission id"})
			return
		}
		pids = append(pids, pid)
	}
	if err := h.rbac.AssignPermissionsToRole(c.Request.Context(), roleID, pids); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not assign permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type assignUserRolesReq struct {
	RoleIDs []string `json:"role_ids" binding:"required,min=1"`
}

func (h *RBACHandler) AssignRolesToUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	var req assignUserRolesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var rids []uuid.UUID
	for _, s := range req.RoleIDs {
		rid, err := uuid.Parse(s)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		rids = append(rids, rid)
	}
	if err := h.rbac.AssignRolesToUser(c.Request.Context(), userID, rids); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not assign roles"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
