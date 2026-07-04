# Auth Capability

## Features

| Feature | Status |
|---------|--------|
| Register | Implemented |
| Login | Implemented |
| Logout (token revocation) | Implemented |
| Refresh token rotation | Implemented |
| Session management | Implemented |
| Password hashing (bcrypt) | Implemented |
| Forgot password | Implemented |
| Reset password | Implemented |
| Email verification | Implemented |
| JWT access token | Implemented |
| RBAC (roles + permissions) | Implemented |
| Permission middleware | Implemented |
| Role middleware | Implemented |
| MFA (TOTP) | Implemented |
| Google OAuth | Implemented |
| Rate limiting | Implemented |
| Account lockout | Implemented |
| User ban | Implemented |
| Audit logging | Implemented |
| Token cleanup | Implemented |

## Quick start

```go
import (
    "github.com/MiraiMagicLab/go-platform-kit/auth"
    "github.com/MiraiMagicLab/go-platform-kit/platform/config"
    "github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

cfg, _ := config.Load(config.FromEnv())
pool, _ := postgres.Open(ctx, cfg.Infra.Postgres)

a, _ := auth.Open(ctx,
    auth.WithConfig(auth.Config{
        JWTAccessSecret:  cfg.Auth.JWTAccessSecret,
        JWTRefreshSecret: cfg.Auth.JWTRefreshSecret,
        Issuer:           "my-app",
    }),
    auth.WithPostgres(pool),
)

// Host owns HTTP
r.POST("/auth/login", func(c *gin.Context) {
    res, err := a.Login(c.Request.Context(), email, password, auth.ClientMeta{
        IP: c.ClientIP(), UA: c.Request.UserAgent(),
    })
    if auth.WriteError(c, err, httpx.CodeAuthInvalidCredentials, 401) { return }
    httpx.Success(c, 200, "success", res, nil)
})

// Protected routes
api := r.Group("/api")
api.Use(a.JWTAuth())
```

## Configuration

See `auth.Config` struct. Key fields:

| Field | Default | Description |
|-------|---------|-------------|
| JWTAccessSecret | required | HMAC secret for access tokens |
| JWTRefreshSecret | required | HMAC secret for refresh tokens |
| AccessTokenTTL | 15m | Access token lifetime |
| RefreshTokenTTL | 720h | Refresh token lifetime |
| DefaultRegisterRole | "user" | Role assigned on register |
| SeedRoles | [admin, user] | Roles created on startup |
| SeedPermissions | [rbac.manage] | Permissions created on startup |

## RBAC

```go
// Middleware
api.Use(a.RequirePermission("courses.write"))
api.Use(a.RequireRole("admin"))
api.Use(a.RequireAccess("courses.write")) // mode-dependent

// Management
a.CreateRole(ctx, "instructor")
a.CreatePermission(ctx, "courses.publish")
a.AssignRolesToUser(ctx, userID, []uuid.UUID{roleID})
a.AssignPermissionsToRole(ctx, roleID, []uuid.UUID{permID})
```

## MFA

```go
setup, _ := a.SetupMFA(ctx, userID, "myapp@example.com")
// Show setup.URI to user (QR code)
a.EnableMFA(ctx, userID, otpCode)
// On login, check for MFARequired error, then:
a.CompleteMFA(ctx, mfaToken, otpCode, meta)
```

## OAuth

```go
url, _ := a.OAuthAuthCodeURL(auth.OAuthGoogle, state)
// Redirect user to url
// On callback:
result, _ := a.OAuthExchange(ctx, auth.OAuthGoogle, code, meta)
```

## Session management

```go
sessions, _ := a.ListSessions(ctx, userID)
a.RevokeSession(ctx, userID, targetID, currentID, jti, exp)
a.RevokeOtherSessions(ctx, userID, keepID)
```
