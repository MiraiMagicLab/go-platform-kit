package auth

import (
	"time"

	"github.com/gin-gonic/gin"

	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
)

// MountReferenceAll registers the default reference auth HTTP routes.
// Prefer host-owned handlers calling [Auth.Login] and related use-case methods.
func (a *Auth) MountReferenceAll(r gin.IRouter) {
	a.mountReferenceCommon(r)
	a.mountReferenceAuth(r)
	a.mountReferenceEmail(r)
	a.mountReferenceMFA(r)
	a.mountReferenceOAuth(r)
	a.mountReferenceRBAC(r)
}

func (a *Auth) mountReferenceCommon(r gin.IRouter) {
	if a.commonMounted {
		return
	}
	r.Use(httpmw.RequestID())
	r.Use(httpmw.AccessLog())
	r.Use(httpmw.CORS(a.cfg.CORSAllowedOrigins))
	a.commonMounted = true
}

func (a *Auth) mountReferenceAuth(r gin.IRouter) {
	loginLimit := httpmw.SensitiveRateLimit(a.rateLimiter, a.memLimiter, "rl:login", a.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := httpmw.SensitiveRateLimit(a.rateLimiter, a.memLimiter, "rl:refresh", a.cfg.RateLimitRefreshPerMinute, time.Minute)
	r.POST("/register", a.authH.Register)
	r.POST("/login", loginLimit, a.authH.Login)
	r.POST("/login/2fa", a.authH.CompleteMFA)
	r.POST("/refresh", refreshLimit, a.authH.Refresh)

	me := r.Group("/")
	me.Use(a.authMW)
	me.POST("/logout", a.authH.Logout)
	me.GET("/me", a.authH.Me)
	if a.sessionH != nil {
		me.GET("/sessions", a.sessionH.List)
		me.DELETE("/sessions/:id", a.sessionH.RevokeOne)
		me.POST("/sessions/revoke-others", a.sessionH.RevokeOthers)
	}
}

func (a *Auth) mountReferenceEmail(r gin.IRouter) {
	forgotLimit := httpmw.SensitiveRateLimit(a.rateLimiter, a.memLimiter, "rl:forgot", a.cfg.RateLimitForgotPerMinute, time.Minute)
	resetLimit := httpmw.SensitiveRateLimit(a.rateLimiter, a.memLimiter, "rl:reset_password", a.cfg.RateLimitPasswordResetPerMinute, time.Minute)
	verifyConfirmLimit := httpmw.SensitiveRateLimit(a.rateLimiter, a.memLimiter, "rl:email_verify_confirm", a.cfg.RateLimitEmailVerifyConfirmPerMinute, time.Minute)
	r.POST("/password/forgot", forgotLimit, a.authH.ForgotPassword)
	r.POST("/password/reset", resetLimit, a.authH.ResetPassword)
	r.POST("/email/verify/confirm", verifyConfirmLimit, a.authH.ConfirmVerifyEmail)

	me := r.Group("/")
	me.Use(a.authMW)
	me.POST("/email/verify/request", a.authH.RequestVerifyEmail)
}

func (a *Auth) mountReferenceMFA(r gin.IRouter) {
	me := r.Group("/")
	me.Use(a.authMW)
	me.POST("/mfa/setup", a.mfaH.Setup)
	me.POST("/mfa/enable", a.mfaH.Enable)
	me.POST("/mfa/disable", a.mfaH.Disable)
}

// MountReferenceOAuth registers Google OAuth login, callback, and exchange routes.
func (a *Auth) MountReferenceOAuth(r gin.IRouter) {
	a.mountReferenceOAuth(r)
}

func (a *Auth) mountReferenceOAuth(r gin.IRouter) {
	r.GET("/oauth/:provider/login", a.oauthH.Login)
	r.GET("/oauth/:provider/callback", a.oauthH.Callback)
	r.POST("/oauth/:provider/exchange", a.oauthH.Exchange)
}

func (a *Auth) mountReferenceRBAC(r gin.IRouter) {
	rbac := r.Group("/")
	rbac.Use(a.authMW)
	rbac.Use(httpmw.RequirePermission(a.rbacSvc, a.cfg.RBACAdminPermission, a.cfg.AdminBypassPermission))
	rbac.POST("/roles", a.rbacH.CreateRole)
	rbac.POST("/permissions", a.rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", a.rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", a.rbacH.AssignRolesToUser)
	rbac.POST("/users/:id/ban", a.rbacH.BanUser)
	rbac.POST("/users/:id/unban", a.rbacH.UnbanUser)
	rbac.DELETE("/users/:id", a.rbacH.DeleteUser)
	rbac.GET("/users", a.rbacH.ListUsers)
}
