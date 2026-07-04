# Go Platform Kit

Shared platform library for MiraiMagicLab Go backends: infrastructure helpers, HTTP conventions, and pluggable capabilities (auth, admin, and more).

## Architecture

```
platform/          # Stable kernel — httpx, log, config, postgres, redis, storage
auth/              # Auth capability (Gin + Postgres + optional Redis)
admin/             # Admin panel schema compiler
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for dependency rules and how to add new capabilities.

## Quick start

```go
import (
    "github.com/MiraiMagicLab/go-platform-kit/auth"
    "github.com/MiraiMagicLab/go-platform-kit/platform/config"
    "github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
    "github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

infra, _ := config.Load(config.FromEnv())
pg, _ := postgres.Open(ctx, infra.Infra.Postgres)
rdb, _ := redis.Open(ctx, infra.Infra.Redis)

a, _ := auth.Open(ctx,
    auth.WithConfig(cfg),
    auth.WithPostgres(pg),
    auth.WithRedis(rdb),
)

r.POST("/auth/login", func(c *gin.Context) {
    res, err := a.Login(c.Request.Context(), email, password, auth.ClientMeta{
        IP: c.ClientIP(), UA: c.Request.UserAgent(),
    })
    if auth.WriteError(c, err, httpx.CodeAuthInvalidCredentials, 401) { return }
    httpx.Success(c, 200, "success", res, nil)
})

api := r.Group("/api")
api.Use(a.JWTAuth())
```

Run the example:

```bash
export DATABASE_URL=postgres://...
export JWT_ACCESS_SECRET=...
export JWT_REFRESH_SECRET=...
go run ./examples/full-stack
```

## Packages

### Platform (stable kernel)

| Import | Purpose |
|--------|---------|
| `platform/config` | Shared infra config (`FromEnv`, `OpenInfra`) |
| `platform/log` | Injectable logger interface |
| `platform/httpx` | JSON API envelope, M00xxxx error codes, recovery, pagination |
| `platform/postgres` | Postgres pool helper (Open/Ping/Close) |
| `platform/redis` | Redis client helper (Open/Ping/Close) |
| `platform/health` | Health check aggregator (Postgres, Redis) |
| `platform/storage` | Cloudflare R2 object store (upload, delete, signed URL) |
| `platform/mail` | SMTP mailer with STARTTLS |
| `platform/transaction` | Generic pgx transaction helper (`WithTx`, `TxFromCtx`) |
| `platform/clock` | Time abstraction for testability (`RealClock`, `FixedClock`) |
| `platform/id` | Pluggable ID generator (`UUIDGenerator`) |

### Capabilities

| Import | Purpose |
|--------|---------|
| `auth` | Authentication, sessions, RBAC, MFA, Google OAuth |
| `admin` | Admin shell compiler + v3 migration |

## Google OAuth

Set in [Google Cloud Console](https://console.cloud.google.com/apis/credentials) a **Web application** OAuth client. Authorized redirect URI:

```
https://your-api.example.com/auth/oauth/google/callback
```

Environment variables (loaded by `auth.ApplyEnv`):

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Yes | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | OAuth client secret |
| `GOOGLE_REDIRECT_URL` | No | Override callback (default: `{PUBLIC_BASE_URL}/auth/oauth/google/callback`) |
| `PUBLIC_BASE_URL` | Yes* | Backend public URL |
| `FRONTEND_BASE_URL` | No | Frontend redirect after login (default: `PUBLIC_BASE_URL`) |

Reference routes: `GET /auth/oauth/google/login`, `GET /auth/oauth/google/callback`, `POST /auth/oauth/google/exchange`.

## Cloudflare R2 storage

Configure via environment (loaded by `config.FromEnv()`):

| Variable | Required | Description |
|----------|----------|-------------|
| `R2_ACCOUNT_ID` | Yes* | Cloudflare account ID |
| `R2_BUCKET` | Yes | Bucket name |
| `R2_ACCESS_KEY` | Yes | R2 API token access key |
| `R2_SECRET_KEY` | Yes | R2 API token secret |
| `R2_PUBLIC_BASE` | No | CDN/public URL prefix (e.g. `https://cdn.example.com`) |
| `R2_ENDPOINT` | No* | Custom S3 endpoint (defaults to `https://{account_id}.r2.cloudflarestorage.com`) |

\* Either `R2_ACCOUNT_ID` or `R2_ENDPOINT` is required.

```go
infra, _ := config.Load(config.FromEnv())
clients, _ := infra.OpenInfra(ctx)
defer clients.Close()

// Upload
_ = clients.Storage.Put(ctx, "avatars/user.png", file, storage.PutOptions{ContentType: "image/png"})
publicURL := clients.Storage.URL("avatars/user.png")
signed, _ := clients.Storage.SignedURL(ctx, "avatars/user.png", 15*time.Minute)
```

## Migrations

Baseline schema v1.0 — single migration for new installs:

```bash
DATABASE_URL=postgres://... go run ./cmd/migrate
```

Or apply directly:

```bash
psql $DATABASE_URL -f sql/schema.sql
```

Files:
- `migrations/0001_baseline.up.sql` — apply schema
- `migrations/0001_baseline.down.sql` — rollback
- `sql/schema.sql` — canonical reference copy

## Testing

```bash
go test ./...
go test -tags=integration ./auth/integration/...   # requires DATABASE_URL
go vet ./...
```

Unit tests cover auth use cases (login, MFA, OAuth, RBAC, session, email), JWT middleware, and platform modules. Integration tests exercise register, login/logout, refresh, MFA, and RBAC against Postgres when `DATABASE_URL` is set.

## Error codes

See [ERROR_CODE_REFERENCE.md](ERROR_CODE_REFERENCE.md).
