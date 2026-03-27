## Embedded Auth Library (Go + Gin + Postgres)

Production-ready starter for an **authentication + authorization** service:

- **Auth**: register/login/refresh/logout, bcrypt hashing
- **Tokens**: short-lived access JWT + long-lived refresh token (atomic rotation, replay detection, revoke)
- **Authorization**: **dynamic RBAC** (permissions stored in DB as strings, not hardcoded)
- **MFA**: TOTP + recovery codes
- **Social login**: Google and Facebook OAuth2
- **Architecture**: clean-ish layers (handler → service → repository)

### Quick start (embedded)

1) Start Postgres (and optionally Redis), then apply the schema in `sql/schema.sql`.

2) Configure env vars:

- `DATABASE_URL` (required) e.g. `postgres://user:pass@localhost:5432/authsvc?sslmode=disable`
- `JWT_ACCESS_SECRET` (required)
- `JWT_REFRESH_SECRET` (required)
- `DATA_ENCRYPTION_KEY_B64` (optional but recommended, base64 of 32-byte key for TOTP secret encryption)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` (required for email verify/reset flows)
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL` (optional)
- `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`, `FACEBOOK_REDIRECT_URL` (optional)
- `PUBLIC_BASE_URL` (default `http://localhost:8080`)

3) Mount into your existing Gin app:

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

cfg := authkit.DefaultConfig()
cfg.JWTAccessSecret = os.Getenv("JWT_ACCESS_SECRET")
cfg.JWTRefreshSecret = os.Getenv("JWT_REFRESH_SECRET")
cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
cfg.GoogleRedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
cfg.DataEncryptionKeyB64 = os.Getenv("DATA_ENCRYPTION_KEY_B64")
cfg.SMTPHost = os.Getenv("SMTP_HOST")
cfg.SMTPPort = 587
cfg.SMTPUser = os.Getenv("SMTP_USER")
cfg.SMTPPass = os.Getenv("SMTP_PASS")
cfg.SMTPFrom = os.Getenv("SMTP_FROM")
cfg.SeedRoles = []string{"admin", "teacher", "student"}
cfg.SeedPermissions = []string{
  "rbac.manage",
  "course.create",
  "course.update",
  "lesson.view",
}
cfg.SeedRolePermissions = map[string][]string{
  "admin": {"rbac.manage", "course.create", "course.update", "lesson.view"},
  "teacher": {"course.create", "course.update", "lesson.view"},
  "student": {"lesson.view"},
}

mod, _ := authkit.New(cfg, pool, rdb)
g := router.Group("/auth")
mod.MountCommon(g)
mod.MountAuth(g)
mod.MountEmail(g)
mod.MountMFA(g)
mod.MountOAuth(g)
mod.MountRBAC(g)
mod.StartBackgroundCleanup(ctx, 30*time.Minute)
```

Or mount with fine-grained options:

```go
opt := authkit.DefaultMountOptions()
opt.RBAC = authkit.RBACEndpoints{} // disable RBAC admin endpoints
opt.OAuth = false                  // disable OAuth routes
mod.MountWithOptions(g, opt)
```

### Customization (library-style)

- Keep core auth logic consistent; customize via `authkit.Config` and `authkit.Hooks`.
- **RBAC admin permission**: `cfg.RBACAdminPermission`
- **Email links/templates**: `cfg.Hooks.BuildVerifyEmailLink`, `cfg.Hooks.BuildResetPasswordLink`, `cfg.Hooks.RenderVerifyEmail`, `cfg.Hooks.RenderResetPassword`

Example hook (custom frontend link):

```go
cfg.Hooks.BuildResetPasswordLink = func(publicBaseURL, token string) string {
  return "https://frontend.example.com/reset-password?token=" + url.QueryEscape(token)
}
```

### Install (private repo)

This library is hosted as a **private** GitHub repo:

- https://github.com/MiraiMagicLab/go-auth-lib

To import it from another Go project, configure:

1) `GOPRIVATE`

```bash
go env -w GOPRIVATE=github.com/MiraiMagicLab/*
```

2) Make sure you have access to the private repo (GitHub auth: SSH key or access token).

3) Add dependency (pin to a tag)

```bash
go get github.com/MiraiMagicLab/go-auth-lib@v1.0.0
```

If you don’t have a tag yet, create and push one in this repo:

```bash
git tag v1.0.0
git push --tags
```

### API

Auth:
- `POST /register`
- `POST /login`
- `POST /refresh`
- `POST /password/forgot`
- `POST /password/reset`
- `POST /email/verify/confirm`
- `POST /login/2fa`
- `POST /logout`
- `GET /me`
- `POST /mfa/setup`
- `POST /mfa/enable`
- `POST /mfa/disable`
- `POST /email/verify/request` (authenticated)
- `GET /oauth/google/login`
- `GET /oauth/facebook/login`

RBAC:
- `POST /roles`
- `POST /permissions`
- `POST /roles/:id/permissions`
- `POST /users/:id/roles`
- `POST /users/:id/ban` (body: `{ "banned_until": "<RFC3339>", "reason": "..." }`)
- `POST /users/:id/unban`

Dynamic roles/permissions can be bootstrapped from host project via:
- `cfg.SeedRoles`
- `cfg.SeedPermissions`
- `cfg.SeedRolePermissions`
- `cfg.RequireEmailVerifiedBeforeLogin` (default `false`)
- `cfg.RateLimitPasswordResetPerMinute` (default `10`)
- `cfg.RateLimitEmailVerifyConfirmPerMinute` (default `10`)

Security and reliability additions:
- request-id + structured access logs on auth routes
- rate limit for sensitive endpoints (`/login`, `/refresh`, `/password/reset`, `/email/verify/confirm`)
- audit log table + write events on register/login/logout/mfa
- encrypted TOTP secrets at rest (when `DATA_ENCRYPTION_KEY_B64` is provided)
- background cleanup job for expired/revoked tokens and old used recovery codes

Migrations:
- `migrations/0001_init.up.sql`
- `migrations/0001_init.down.sql`

Apply schema (recommended):
```bash
psql "$DATABASE_URL" -f migrations/0001_init.up.sql
```

### Security notes

- Access token invalidation uses both `token_version` checks and optional Redis denylist by `jti` on logout.
- Refresh tokens are stored hashed and rotated in a DB transaction (`SELECT ... FOR UPDATE`) to prevent race issues.
- Refresh token replay attempts force-revoke active refresh tokens and invalidate current access lineage (`token_version` increment).

### API response contract

All non-redirect API endpoints return a standard envelope:

```json
{
  "success": true,
  "message": "Login success",
  "errorMessage": {
    "errorCode": "auth.invalid_email",
    "message": "Invalid email format",
    "params": {}
  },
  "data": {}
}
```

- `message` is fallback English text.
- `errorMessage.errorCode` is stable i18n key for client-side translation.
- Frontend/mobile can map `errorCode` to localized text by user locale.

This project now focuses on embedded library mode only (no standalone microservice SDK client).

### Example project

A runnable embedded example is available at `examples/embedded/main.go`.

Run it:

```bash
set DATABASE_URL=postgres://user:pass@localhost:5432/authsvc?sslmode=disable
set JWT_ACCESS_SECRET=your-access-secret
set JWT_REFRESH_SECRET=your-refresh-secret
go run ./examples/embedded
```

Auth routes will be mounted at `/auth/*` (e.g. `/auth/login`, `/auth/register`).

