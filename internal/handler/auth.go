package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/repository"
	"github.com/tienh/authsvc/internal/response"
	"github.com/tienh/authsvc/internal/service"
)

type AuthHandler struct {
	auth  *service.AuthService
	rbac  *service.RBACService
	users repository.UserRepository
}

func NewAuthHandler(auth *service.AuthService, rbac *service.RBACService, users repository.UserRepository) *AuthHandler {
	return &AuthHandler{auth: auth, rbac: rbac, users: users}
}

type registerReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	if !strings.Contains(req.Email, "@") {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidEmail)
		return
	}
	if len(req.Password) < 8 {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidPassword)
		return
	}
	id, err := h.auth.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthRegisterFailed)
		return
	}
	response.Success(c, http.StatusCreated, "User registered", gin.H{"id": id.String()})
}

type loginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	res, err := h.auth.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidCredentials)
		return
	}
	response.Success(c, http.StatusOK, "Login success", res)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	res, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidRefresh)
		return
	}
	response.Success(c, http.StatusOK, "Refresh success", res)
}

type completeMFAReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

func (h *AuthHandler) CompleteMFA(c *gin.Context) {
	var req completeMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	res, err := h.auth.CompleteMFA(c.Request.Context(), req.MFAToken, req.Code)
	if err != nil {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidMFA)
		return
	}
	response.Success(c, http.StatusOK, "MFA verification success", res)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
		return
	}
	jti, exp, ok := middleware.AccessTokenMetaFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
		return
	}
	if err := h.auth.Logout(c.Request.Context(), userID, jti, exp); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeAuthLogoutFailed)
		return
	}
	response.Success(c, http.StatusOK, "Logout success", gin.H{"ok": true})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
		return
	}

	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
		return
	}

	roles, _ := h.rbac.ListUserRoles(c.Request.Context(), userID)
	perms, _ := h.rbac.ListUserPermissions(c.Request.Context(), userID)

	response.Success(c, http.StatusOK, "User profile", gin.H{
		"id":          u.ID.String(),
		"email":       u.Email,
		"roles":       roles,
		"permissions": perms,
	})
}
