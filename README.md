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

mod, _ := auth.New(ctx,
    auth.WithConfig(cfg),
    auth.WithPostgres(pg),
    auth.WithRedis(rdb),
)
mod.MountAll(r.Group("/auth"))
```

Run the example:

```bash
export DATABASE_URL=postgres://...
export JWT_ACCESS_SECRET=...
export JWT_REFRESH_SECRET=...
go run ./examples/full-stack
```

## Packages

| Import | Purpose |
|--------|---------|
| `platform/httpx` | JSON API envelope + M00xxxx error codes |
| `platform/log` | Injectable logger interface |
| `platform/config` | Shared infra config (`FromEnv`) |
| `platform/postgres` | Postgres pool helper |
| `platform/redis` | Redis client helper |
| `platform/storage` | Object store interface (R2/S3 stub) |
| `auth` | Authentication, sessions, RBAC, MFA, OAuth |
| `admin` | Admin shell compiler + v3 migration |

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
go test -tags=integration ./auth/integration/...
go vet ./...
```

## Error codes

See [ERROR_CODE_REFERENCE.md](ERROR_CODE_REFERENCE.md).
