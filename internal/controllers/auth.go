package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/internal/utils"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type AuthHandler struct {
	auth          *services.AuthService
	email         *services.EmailService
	rbac          *services.RBACService
	users         *postgres.UserRepo
	audit         *services.AuditService
	lifecycle     *AuthLifecycle
	emailValidate utils.EmailValidator
}

func NewAuthHandler(auth *services.AuthService, email *services.EmailService, rbac *services.RBACService, users *postgres.UserRepo, audit *services.AuditService, lifecycle *AuthLifecycle, emailValidate utils.EmailValidator) *AuthHandler {
	if emailValidate == nil {
		emailValidate = utils.DefaultEmailValidator
	}
	return &AuthHandler{auth: auth, email: email, rbac: rbac, users: users, audit: audit, lifecycle: lifecycle, emailValidate: emailValidate}
}

type registerReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if !h.emailValidate(req.Email) {
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidEmail)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidEmail, nil)
		return
	}
	if len(req.Password) < 8 {
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidPassword)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidPassword, nil)
		return
	}
	id, err := h.auth.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthRegisterFailed)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthRegisterFailed, nil)
		h.audit.Log(c.Request.Context(), nil, "auth.register", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	h.audit.Log(c.Request.Context(), &id, "auth.register", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
	email := req.Email
	fireAfterSessionIssued(h.lifecycle, "register", id, &email, c.ClientIP(), c.Request.UserAgent())
	response.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type loginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	res, err := h.auth.Login(c.Request.Context(), req.Email, req.Password, services.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	})
	if err != nil {
		if b, ok := err.(services.ErrUserBanned); ok {
			params := map[string]interface{}{}
			if b.Until != nil {
				params["banned_until"] = b.Until.UTC().Format("2006-01-02T15:04:05Z")
			}
			if b.Reason != nil {
				params["reason"] = *b.Reason
			}
			middleware.SetAuthErrorCode(c, response.CodeAuthUserBanned)
			response.Fail(c, http.StatusForbidden, response.CodeAuthUserBanned, params)
			return
		}
		if lk, ok := err.(services.ErrAccountLocked); ok {
			params := map[string]interface{}{}
			if lk.Until != nil {
				params["locked_until"] = lk.Until.UTC().Format("2006-01-02T15:04:05Z")
			}
			middleware.SetAuthErrorCode(c, response.CodeAuthAccountLocked)
			response.Fail(c, http.StatusForbidden, response.CodeAuthAccountLocked, params)
			return
		}
		if _, ok := err.(services.ErrEmailNotVerified); ok {
			middleware.SetAuthErrorCode(c, response.CodeAuthEmailNotVerified)
			response.FailCode(c, http.StatusForbidden, response.CodeAuthEmailNotVerified, nil)
			h.audit.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
			return
		}
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidCredentials)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidCredentials, nil)
		h.audit.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.login", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	email := req.Email
	fireAfterSessionIssued(h.lifecycle, "login", res.UserID, &email, c.ClientIP(), c.Request.UserAgent())
	response.Success(c, http.StatusOK, "success", res, nil)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	deviceName := ""
	res, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken, services.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	}, deviceName)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidRefresh)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidRefresh, nil)
		return
	}
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.refresh", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", res, nil)
}

type completeMFAReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

func (h *AuthHandler) CompleteMFA(c *gin.Context) {
	var req completeMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	res, err := h.auth.CompleteMFA(c.Request.Context(), req.MFAToken, req.Code, services.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	})
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidMFA)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthInvalidMFA, nil)
		return
	}
	h.audit.Log(c.Request.Context(), &res.UserID, "auth.mfa_complete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	fireAfterSessionIssued(h.lifecycle, "mfa_complete", res.UserID, nil, c.ClientIP(), c.Request.UserAgent())
	response.Success(c, http.StatusOK, "success", res, nil)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	jti, exp, ok := middleware.AccessTokenMetaFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	if err := h.auth.Logout(c.Request.Context(), userID, jti, exp); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthLogoutFailed)
		response.FailCode(c, http.StatusInternalServerError, response.CodeAuthLogoutFailed, nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "auth.logout", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}

	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}

	roles, _ := h.rbac.ListUserRoles(c.Request.Context(), userID)
	perms, _ := h.rbac.ListUserPermissions(c.Request.Context(), userID)

	response.Success(c, http.StatusOK, "success", gin.H{
		"id":          u.ID.String(),
		"email":       u.Email,
		"roles":       roles,
		"permissions": perms,
	}, nil)
}

func (h *AuthHandler) RequestVerifyEmail(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, response.CodeAuthUnauthorized)
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	if h.email == nil || h.email.RequestVerifyEmail(c.Request.Context(), userID) != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthEmailSendFailed)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthEmailSendFailed, nil)
		h.audit.Log(c.Request.Context(), &userID, "auth.email_verify_request", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "auth.email_verify_request", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type confirmTokenReq struct {
	Token string `json:"token" binding:"required"`
}

func (h *AuthHandler) ConfirmVerifyEmail(c *gin.Context) {
	var req confirmTokenReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if h.email == nil || h.email.ConfirmVerifyEmail(c.Request.Context(), req.Token) != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthInvalidActionToken)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthInvalidActionToken, nil)
		h.audit.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.audit.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}

type forgotPasswordReq struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if h.email == nil || h.email.ForgotPassword(c.Request.Context(), req.Email) != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthEmailSendFailed)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthEmailSendFailed, nil)
		h.audit.Log(c.Request.Context(), nil, "auth.password_forgot", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.audit.Log(c.Request.Context(), nil, "auth.password_forgot", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
}

type resetPasswordReq struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, response.CodeCommonBadRequest)
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if h.email == nil || h.email.ResetPassword(c.Request.Context(), req.Token, req.NewPassword) != nil {
		middleware.SetAuthErrorCode(c, response.CodeAuthPasswordResetFailed)
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthPasswordResetFailed, nil)
		h.audit.Log(c.Request.Context(), nil, "auth.password_reset", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.audit.Log(c.Request.Context(), nil, "auth.password_reset", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}
