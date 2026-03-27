package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/internal/repository"
	"github.com/MiraiMagicLab/go-auth-lib/internal/response"
	"github.com/MiraiMagicLab/go-auth-lib/internal/service"
)

type AuthHandler struct {
	auth  *service.AuthService
	email *service.EmailService
	rbac  *service.RBACService
	users repository.UserRepository
	audit *service.AuditService
}

func NewAuthHandler(auth *service.AuthService, email *service.EmailService, rbac *service.RBACService, users repository.UserRepository, audit *service.AuditService) *AuthHandler {
	return &AuthHandler{auth: auth, email: email, rbac: rbac, users: users, audit: audit}
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
		h.audit.Log(c.Request.Context(), nil, "auth.register", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	h.audit.Log(c.Request.Context(), &id, "auth.register", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
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
		if b, ok := err.(service.ErrUserBanned); ok {
			params := map[string]interface{}{}
			if b.Until != nil {
				params["banned_until"] = b.Until.UTC().Format("2006-01-02T15:04:05Z")
			}
			if b.Reason != nil {
				params["reason"] = *b.Reason
			}
			response.Fail(c, http.StatusForbidden, response.CodeAuthUserBanned, response.DefaultMessage(response.CodeAuthUserBanned), params)
			return
		}
		if _, ok := err.(service.ErrEmailNotVerified); ok {
			response.FailCode(c, http.StatusForbidden, response.CodeAuthEmailNotVerified)
			h.audit.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
			return
		}
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidCredentials)
		h.audit.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.login", "success", c.ClientIP(), c.Request.UserAgent(), nil)
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
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.refresh", "success", c.ClientIP(), c.Request.UserAgent(), nil)
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
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.mfa_complete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
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
	h.audit.Log(c.Request.Context(), &userID, "auth.logout", "success", c.ClientIP(), c.Request.UserAgent(), nil)
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

func (h *AuthHandler) RequestVerifyEmail(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized)
		return
	}
	if h.email == nil || h.email.RequestVerifyEmail(c.Request.Context(), userID) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthEmailSendFailed)
		h.audit.Log(c.Request.Context(), &userID, "auth.email_verify_request", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "auth.email_verify_request", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "Verification email sent", gin.H{"ok": true})
}

type confirmTokenReq struct {
	Token string `json:"token" binding:"required"`
}

func (h *AuthHandler) ConfirmVerifyEmail(c *gin.Context) {
	var req confirmTokenReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	if h.email == nil || h.email.ConfirmVerifyEmail(c.Request.Context(), req.Token) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidActionToken)
		h.audit.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	response.Success(c, http.StatusOK, "Email verified", gin.H{"ok": true})
	h.audit.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}

type forgotPasswordReq struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	if h.email == nil || h.email.ForgotPassword(c.Request.Context(), req.Email) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthEmailSendFailed)
		h.audit.Log(c.Request.Context(), nil, "auth.password_forgot", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	response.Success(c, http.StatusOK, "If account exists, reset email sent", gin.H{"ok": true})
	h.audit.Log(c.Request.Context(), nil, "auth.password_forgot", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
}

type resetPasswordReq struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest)
		return
	}
	if h.email == nil || h.email.ResetPassword(c.Request.Context(), req.Token, req.NewPassword) != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthPasswordResetFailed)
		h.audit.Log(c.Request.Context(), nil, "auth.password_reset", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	response.Success(c, http.StatusOK, "Password reset success", gin.H{"ok": true})
	h.audit.Log(c.Request.Context(), nil, "auth.password_reset", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}
