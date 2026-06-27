package gin

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/audit"
	authsvc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/auth"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/email"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// Lifecycle holds callbacks that fire after session issuance.
type Lifecycle struct {
	AfterSessionIssued func(ctx *gin.Context, reason string, userID string, emailAddr *string, ip, ua string)
}

// EmailValidator validates email format.
type EmailValidator func(string) bool

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	auth          *authsvc.AuthService
	emailSvc      *email.EmailService
	rbacSvc       *rbac.RBACService
	users         store.UserRepository
	auditSvc      *audit.AuditService
	lifecycle     *Lifecycle
	emailValidate EmailValidator
}

// NewAuthHandler creates an AuthHandler with the given dependencies. If emailValidate
// is nil, a default RFC 5322 validator is used.
func NewAuthHandler(
	authSvc *authsvc.AuthService,
	emailSvc *email.EmailService,
	rbacSvc *rbac.RBACService,
	users store.UserRepository,
	auditSvc *audit.AuditService,
	lifecycle *Lifecycle,
	emailValidate EmailValidator,
) *AuthHandler {
	if emailValidate == nil {
		emailValidate = defaultEmailValidator
	}
	return &AuthHandler{
		auth:          authSvc,
		emailSvc:      emailSvc,
		rbacSvc:       rbacSvc,
		users:         users,
		auditSvc:      auditSvc,
		lifecycle:     lifecycle,
		emailValidate: emailValidate,
	}
}

type registerReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// Register handles POST /register. It validates email and password format,
// creates a new user account, and returns the created user ID.
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if !h.emailValidate(req.Email) {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidEmail)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthInvalidEmail, nil)
		return
	}
	if len(req.Password) < 8 {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidPassword)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthInvalidPassword, nil)
		return
	}
	id, err := h.auth.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		slog.Warn("auth.register failed", "email", req.Email, "error", err, "ip", c.ClientIP())
		middleware.SetAuthErrorCode(c, httpx.CodeAuthRegisterFailed)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthRegisterFailed, nil)
		h.auditSvc.Log(c.Request.Context(), nil, "auth.register", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	slog.Info("auth.register success", "user_id", id, "email", req.Email, "ip", c.ClientIP())
	h.auditSvc.Log(c.Request.Context(), &id, "auth.register", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
	emailStr := req.Email
	fireAfterSessionIssued(h.lifecycle, c, "register", id.String(), &emailStr, c.ClientIP(), c.Request.UserAgent())
	httpx.Success(c, http.StatusCreated, "success", gin.H{"id": id.String()}, nil)
}

type loginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login handles POST /login. It authenticates the user's credentials and returns
// access/refresh tokens, or a MFA challenge token when MFA is enabled.
// It returns specific error codes for banned, locked, or email-unverified accounts.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	res, err := h.auth.Login(c.Request.Context(), req.Email, req.Password, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	})
	if err != nil {
		slog.Warn("auth.login failed", "email", req.Email, "error", err, "ip", c.ClientIP())
		if b, ok := err.(domain.ErrUserBanned); ok {
			params := map[string]interface{}{}
			if b.Until != nil {
				params["banned_until"] = b.Until.UTC().Format("2006-01-02T15:04:05Z")
			}
			if b.Reason != nil {
				params["reason"] = *b.Reason
			}
			middleware.SetAuthErrorCode(c, httpx.CodeAuthUserBanned)
			httpx.Fail(c, http.StatusForbidden, httpx.CodeAuthUserBanned, params)
			return
		}
		if lk, ok := err.(domain.ErrAccountLocked); ok {
			params := map[string]interface{}{}
			if lk.Until != nil {
				params["locked_until"] = lk.Until.UTC().Format("2006-01-02T15:04:05Z")
			}
			middleware.SetAuthErrorCode(c, httpx.CodeAuthAccountLocked)
			httpx.Fail(c, http.StatusForbidden, httpx.CodeAuthAccountLocked, params)
			return
		}
		if _, ok := err.(domain.ErrEmailNotVerified); ok {
			middleware.SetAuthErrorCode(c, httpx.CodeAuthEmailNotVerified)
			httpx.FailCode(c, http.StatusForbidden, httpx.CodeAuthEmailNotVerified, nil)
			h.auditSvc.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
			return
		}
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidCredentials)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthInvalidCredentials, nil)
		h.auditSvc.Log(c.Request.Context(), nil, "auth.login", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	slog.Info("auth.login success", "user_id", res.UserID, "email", req.Email, "ip", c.ClientIP())
	h.auditSvc.Log(c.Request.Context(), &res.UserID, "auth.login", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	emailStr := req.Email
	fireAfterSessionIssued(h.lifecycle, c, "login", res.UserID.String(), &emailStr, c.ClientIP(), c.Request.UserAgent())
	httpx.Success(c, http.StatusOK, "success", res, nil)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Refresh handles POST /refresh. It rotates the refresh token and returns a new
// access/refresh token pair.
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	res, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	}, "")
	if err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidRefresh)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthInvalidRefresh, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &res.UserID, "auth.refresh", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", res, nil)
}

type completeMFAReq struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// CompleteMFA handles POST /mfa/complete. It validates the TOTP code against the
// MFA challenge token and issues a full session with access/refresh tokens.
func (h *AuthHandler) CompleteMFA(c *gin.Context) {
	var req completeMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	res, err := h.auth.CompleteMFA(c.Request.Context(), req.MFAToken, req.Code, domain.ClientMeta{
		IP: c.ClientIP(),
		UA: c.Request.UserAgent(),
	})
	if err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidMFA)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeAuthInvalidMFA, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &res.UserID, "auth.mfa_complete", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	fireAfterSessionIssued(h.lifecycle, c, "mfa_complete", res.UserID.String(), nil, c.ClientIP(), c.Request.UserAgent())
	httpx.Success(c, http.StatusOK, "success", res, nil)
}

// Logout handles POST /logout. It adds the current access token JTI to the denylist
// and revokes all refresh tokens for the current session.
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, httpx.CodeUnauthorized)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	jti, exp, ok := middleware.AccessTokenMetaFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, httpx.CodeUnauthorized)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	if err := h.auth.Logout(c.Request.Context(), userID, jti, exp); err != nil {
		slog.Error("auth.logout failed", "user_id", userID, "error", err)
		middleware.SetAuthErrorCode(c, httpx.CodeAuthLogoutFailed)
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeAuthLogoutFailed, nil)
		return
	}
	slog.Info("auth.logout success", "user_id", userID, "ip", c.ClientIP())
	h.auditSvc.Log(c.Request.Context(), &userID, "auth.logout", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

// Me handles GET /me. It returns the authenticated user's profile, roles, and permissions.
func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, httpx.CodeUnauthorized)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}

	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeUnauthorized)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}

	roles, _ := h.rbacSvc.ListUserRoles(c.Request.Context(), userID)
	perms, _ := h.rbacSvc.ListUserPermissions(c.Request.Context(), userID)

	httpx.Success(c, http.StatusOK, "success", gin.H{
		"id":          u.ID.String(),
		"email":       u.Email,
		"roles":       roles,
		"permissions": perms,
	}, nil)
}

// RequestVerifyEmail handles POST /email/verify/request. It generates and sends
// a verification email to the authenticated user's email address.
func (h *AuthHandler) RequestVerifyEmail(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		middleware.SetAuthErrorCode(c, httpx.CodeUnauthorized)
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	if h.emailSvc == nil || h.emailSvc.RequestVerifyEmail(c.Request.Context(), userID) != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthEmailSendFailed)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthEmailSendFailed, nil)
		h.auditSvc.Log(c.Request.Context(), &userID, "auth.email_verify_request", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "auth.email_verify_request", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type confirmTokenReq struct {
	Token string `json:"token" binding:"required"`
}

// ConfirmVerifyEmail handles POST /email/verify/confirm. It validates the verification
// token and marks the user's email as verified.
func (h *AuthHandler) ConfirmVerifyEmail(c *gin.Context) {
	var req confirmTokenReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if h.emailSvc == nil || h.emailSvc.ConfirmVerifyEmail(c.Request.Context(), req.Token) != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthInvalidActionToken)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthInvalidActionToken, nil)
		h.auditSvc.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.auditSvc.Log(c.Request.Context(), nil, "auth.email_verify_confirm", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}

type forgotPasswordReq struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPassword handles POST /password/forgot. It sends a password reset token
// (OTP code or link depending on configuration) to the specified email address.
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if h.emailSvc == nil || h.emailSvc.ForgotPassword(c.Request.Context(), req.Email) != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthEmailSendFailed)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthEmailSendFailed, nil)
		h.auditSvc.Log(c.Request.Context(), nil, "auth.password_forgot", "failed", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
		return
	}
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.auditSvc.Log(c.Request.Context(), nil, "auth.password_forgot", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"email": req.Email})
}

type resetPasswordReq struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// ResetPassword handles POST /password/reset. It validates the reset token and
// sets a new password for the user, revoking all existing sessions.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeBadRequest)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if h.emailSvc == nil || h.emailSvc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword) != nil {
		middleware.SetAuthErrorCode(c, httpx.CodeAuthPasswordResetFailed)
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeAuthPasswordResetFailed, nil)
		h.auditSvc.Log(c.Request.Context(), nil, "auth.password_reset", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
	h.auditSvc.Log(c.Request.Context(), nil, "auth.password_reset", "success", c.ClientIP(), c.Request.UserAgent(), nil)
}

func fireAfterSessionIssued(lc *Lifecycle, c *gin.Context, reason, userID string, emailAddr *string, ip, ua string) {
	if lc != nil && lc.AfterSessionIssued != nil {
		go lc.AfterSessionIssued(c, reason, userID, emailAddr, ip, ua)
	}
}

func defaultEmailValidator(email string) bool {
	return len(email) > 0 && len(email) <= 254
}
