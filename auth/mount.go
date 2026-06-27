package auth

import (
	"time"

	"github.com/gin-gonic/gin"

	httpmw "github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin/middleware"
)

// MountOptions provides fine-grained control over which endpoints are mounted.
type MountOptions struct {
	Common bool
	Auth   AuthEndpoints
	Email  EmailEndpoints
	MFA    MFAEndpoints
	OAuth  bool
	RBAC   RBACEndpoints
}

// AuthEndpoints controls which auth endpoints are mounted.
type AuthEndpoints struct {
	Register bool
	Login    bool
	Login2FA bool
	Refresh  bool
	Logout   bool
	Me       bool
	Sessions bool
}

// EmailEndpoints controls which email endpoints are mounted.
type EmailEndpoints struct {
	ForgotPassword      bool
	ResetPassword       bool
	VerifyConfirmPublic bool
	VerifyRequestAuthed bool
}

// MFAEndpoints controls which MFA endpoints are mounted.
type MFAEndpoints struct {
	Setup   bool
	Enable  bool
	Disable bool
}

// RBACEndpoints controls which RBAC admin endpoints are mounted.
type RBACEndpoints struct {
	ManageRoles       bool
	ManagePermissions bool
	AssignRolePerms   bool
	AssignUserRoles   bool
	BanUser           bool
	UnbanUser         bool
	DeleteUser        bool
	ListUsers         bool
}

// DefaultMountOptions returns MountOptions with all endpoints enabled.
func DefaultMountOptions() MountOptions {
	return MountOptions{
		Common: true,
		Auth: AuthEndpoints{
			Register: true,
			Login:    true,
			Login2FA: true,
			Refresh:  true,
			Logout:   true,
			Me:       true,
			Sessions: true,
		},
		Email: EmailEndpoints{
			ForgotPassword:      true,
			ResetPassword:       true,
			VerifyConfirmPublic: true,
			VerifyRequestAuthed: true,
		},
		MFA: MFAEndpoints{
			Setup:   true,
			Enable:  true,
			Disable: true,
		},
		OAuth: true,
		RBAC: RBACEndpoints{
			ManageRoles:       true,
			ManagePermissions: true,
			AssignRolePerms:   true,
			AssignUserRoles:   true,
			BanUser:           true,
			UnbanUser:         true,
			DeleteUser:        true,
			ListUsers:         true,
		},
	}
}

func (m *Module) MountCommon(r gin.IRouter) {
	if m.commonMounted {
		return
	}
	r.Use(httpmw.RequestID())
	r.Use(httpmw.AccessLog())
	r.Use(httpmw.CORS(m.cfg.CORSAllowedOrigins))
	m.commonMounted = true
}

func (m *Module) MountAuth(r gin.IRouter) {
	loginLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:login", m.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:refresh", m.cfg.RateLimitRefreshPerMinute, time.Minute)
	r.POST("/register", m.authH.Register)
	r.POST("/login", loginLimit, m.authH.Login)
	r.POST("/login/2fa", m.authH.CompleteMFA)
	r.POST("/refresh", refreshLimit, m.authH.Refresh)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/logout", m.authH.Logout)
	me.GET("/me", m.authH.Me)
	if m.sessionH != nil {
		me.GET("/sessions", m.sessionH.List)
		me.DELETE("/sessions/:id", m.sessionH.RevokeOne)
		me.POST("/sessions/revoke-others", m.sessionH.RevokeOthers)
	}
}

func (m *Module) MountEmail(r gin.IRouter) {
	forgotLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:forgot", m.cfg.RateLimitForgotPerMinute, time.Minute)
	resetLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:reset_password", m.cfg.RateLimitPasswordResetPerMinute, time.Minute)
	verifyConfirmLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:email_verify_confirm", m.cfg.RateLimitEmailVerifyConfirmPerMinute, time.Minute)
	r.POST("/password/forgot", forgotLimit, m.authH.ForgotPassword)
	r.POST("/password/reset", resetLimit, m.authH.ResetPassword)
	r.POST("/email/verify/confirm", verifyConfirmLimit, m.authH.ConfirmVerifyEmail)

	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/email/verify/request", m.authH.RequestVerifyEmail)
}

func (m *Module) MountMFA(r gin.IRouter) {
	me := r.Group("/")
	me.Use(m.authMW)
	me.POST("/mfa/setup", m.mfaH.Setup)
	me.POST("/mfa/enable", m.mfaH.Enable)
	me.POST("/mfa/disable", m.mfaH.Disable)
}

func (m *Module) MountOAuth(r gin.IRouter) {
	r.GET("/oauth/:provider/login", m.oauthH.Login)
	r.GET("/oauth/:provider/callback", m.oauthH.Callback)
}

func (m *Module) MountRBAC(r gin.IRouter) {
	rbac := r.Group("/")
	rbac.Use(m.authMW)
	rbac.Use(httpmw.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission, m.cfg.AdminBypassPermission))
	rbac.POST("/roles", m.rbacH.CreateRole)
	rbac.POST("/permissions", m.rbacH.CreatePermission)
	rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
	rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
	rbac.POST("/users/:id/ban", m.rbacH.BanUser)
	rbac.POST("/users/:id/unban", m.rbacH.UnbanUser)
	rbac.DELETE("/users/:id", m.rbacH.DeleteUser)
	rbac.GET("/users", m.rbacH.ListUsers)
}

func (m *Module) MountAll(r gin.IRouter) {
	m.MountCommon(r)
	m.MountAuth(r)
	m.MountEmail(r)
	m.MountMFA(r)
	m.MountOAuth(r)
	m.MountRBAC(r)
}

func (m *Module) MountWithOptions(r gin.IRouter, opt MountOptions) {
	if opt.Common {
		m.MountCommon(r)
	}

	loginLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:login", m.cfg.RateLimitLoginPerMinute, time.Minute)
	refreshLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:refresh", m.cfg.RateLimitRefreshPerMinute, time.Minute)
	forgotLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:forgot", m.cfg.RateLimitForgotPerMinute, time.Minute)
	resetLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:reset_password", m.cfg.RateLimitPasswordResetPerMinute, time.Minute)
	verifyConfirmLimit := httpmw.SensitiveRateLimit(m.redis, m.memLimiter, "rl:email_verify_confirm", m.cfg.RateLimitEmailVerifyConfirmPerMinute, time.Minute)

	if opt.Auth.Register {
		r.POST("/register", m.authH.Register)
	}
	if opt.Auth.Login {
		r.POST("/login", loginLimit, m.authH.Login)
	}
	if opt.Auth.Login2FA {
		r.POST("/login/2fa", m.authH.CompleteMFA)
	}
	if opt.Auth.Refresh {
		r.POST("/refresh", refreshLimit, m.authH.Refresh)
	}

	if opt.Email.ForgotPassword {
		r.POST("/password/forgot", forgotLimit, m.authH.ForgotPassword)
	}
	if opt.Email.ResetPassword {
		r.POST("/password/reset", resetLimit, m.authH.ResetPassword)
	}
	if opt.Email.VerifyConfirmPublic {
		r.POST("/email/verify/confirm", verifyConfirmLimit, m.authH.ConfirmVerifyEmail)
	}

	if opt.OAuth {
		r.GET("/oauth/:provider/login", m.oauthH.Login)
		r.GET("/oauth/:provider/callback", m.oauthH.Callback)
	}

	authed := r.Group("/")
	authed.Use(m.authMW)

	if opt.Auth.Logout {
		authed.POST("/logout", m.authH.Logout)
	}
	if opt.Auth.Me {
		authed.GET("/me", m.authH.Me)
	}
	if opt.Auth.Sessions && m.sessionH != nil {
		authed.GET("/sessions", m.sessionH.List)
		authed.DELETE("/sessions/:id", m.sessionH.RevokeOne)
		authed.POST("/sessions/revoke-others", m.sessionH.RevokeOthers)
	}
	if opt.MFA.Setup {
		authed.POST("/mfa/setup", m.mfaH.Setup)
	}
	if opt.MFA.Enable {
		authed.POST("/mfa/enable", m.mfaH.Enable)
	}
	if opt.MFA.Disable {
		authed.POST("/mfa/disable", m.mfaH.Disable)
	}
	if opt.Email.VerifyRequestAuthed {
		authed.POST("/email/verify/request", m.authH.RequestVerifyEmail)
	}

	if opt.RBAC.ManageRoles || opt.RBAC.ManagePermissions || opt.RBAC.AssignRolePerms || opt.RBAC.AssignUserRoles || opt.RBAC.BanUser || opt.RBAC.UnbanUser || opt.RBAC.DeleteUser || opt.RBAC.ListUsers {
		rbac := r.Group("/")
		rbac.Use(m.authMW)
		rbac.Use(httpmw.RequirePermission(m.rbacSvc, m.cfg.RBACAdminPermission, m.cfg.AdminBypassPermission))
		if opt.RBAC.ManageRoles {
			rbac.POST("/roles", m.rbacH.CreateRole)
		}
		if opt.RBAC.ManagePermissions {
			rbac.POST("/permissions", m.rbacH.CreatePermission)
		}
		if opt.RBAC.AssignRolePerms {
			rbac.POST("/roles/:id/permissions", m.rbacH.AssignPermissionsToRole)
		}
		if opt.RBAC.AssignUserRoles {
			rbac.POST("/users/:id/roles", m.rbacH.AssignRolesToUser)
		}
		if opt.RBAC.BanUser {
			rbac.POST("/users/:id/ban", m.rbacH.BanUser)
		}
		if opt.RBAC.UnbanUser {
			rbac.POST("/users/:id/unban", m.rbacH.UnbanUser)
		}
		if opt.RBAC.DeleteUser {
			rbac.DELETE("/users/:id", m.rbacH.DeleteUser)
		}
		if opt.RBAC.ListUsers {
			rbac.GET("/users", m.rbacH.ListUsers)
		}
	}
}
