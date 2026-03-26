## Auth Service (Go + Gin + Postgres) with Dynamic RBAC

Production-ready starter for an **authentication + authorization** service:

- **Auth**: register/login/refresh/logout, bcrypt hashing
- **Tokens**: short-lived access JWT + long-lived refresh token (atomic rotation, replay detection, revoke)
- **Authorization**: **dynamic RBAC** (permissions stored in DB as strings, not hardcoded)
- **MFA**: TOTP + recovery codes
- **Social login**: Google and Facebook OAuth2
- **Architecture**: clean-ish layers (handler → service → repository)

### Quick start

1) Start Postgres (and optionally Redis), then apply the schema in `sql/schema.sql`.

2) Configure env vars:

- `HTTP_ADDR` (default `:8080`)
- `DATABASE_URL` (required) e.g. `postgres://user:pass@localhost:5432/authsvc?sslmode=disable`
- `REDIS_URL` (optional) e.g. `redis://localhost:6379/0`
- `JWT_ACCESS_SECRET` (required)
- `JWT_REFRESH_SECRET` (required)
- `ACCESS_TOKEN_TTL` (default `15m`)
- `REFRESH_TOKEN_TTL` (default `720h`)
- `PERMISSIONS_CACHE_TTL` (default `30s`)
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL` (optional)
- `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`, `FACEBOOK_REDIRECT_URL` (optional)
- `PUBLIC_BASE_URL` (default `http://localhost:8080`)

3) Run:

```bash
go run ./cmd/api
```

### API

Auth:
- `POST /register`
- `POST /login`
- `POST /refresh`
- `POST /login/2fa`
- `POST /logout`
- `GET /me`
- `POST /mfa/setup`
- `POST /mfa/enable`
- `POST /mfa/disable`
- `GET /oauth/google/login`
- `GET /oauth/facebook/login`

RBAC:
- `POST /roles`
- `POST /permissions`
- `POST /roles/:id/permissions`
- `POST /users/:id/roles`

Example protected route:
- `POST /courses` requires permission `course.create`

### Security notes

- Access token invalidation uses both `token_version` checks and optional Redis denylist by `jti` on logout.
- Refresh tokens are stored hashed and rotated in a DB transaction (`SELECT ... FOR UPDATE`) to prevent race issues.
- Refresh token replay attempts force-revoke active refresh tokens and invalidate current access lineage (`token_version` increment).

