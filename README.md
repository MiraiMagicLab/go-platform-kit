## Auth Service (Go + Gin + Postgres) with Dynamic RBAC

Production-ready-ish starter for an **authentication + authorization** service:

- **Auth**: register/login/refresh/logout, bcrypt hashing
- **Tokens**: short-lived access JWT + long-lived refresh token (rotation + revocation)
- **Authorization**: **dynamic RBAC** (permissions stored in DB as strings, not hardcoded)
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

3) Run:

```bash
go run ./cmd/api
```

### API

Auth:
- `POST /register`
- `POST /login`
- `POST /refresh`
- `POST /logout`
- `GET /me`

RBAC:
- `POST /roles`
- `POST /permissions`
- `POST /roles/:id/permissions`
- `POST /users/:id/roles`

Example protected route:
- `POST /courses` requires permission `course.create`

