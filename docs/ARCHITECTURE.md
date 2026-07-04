# Architecture

Go Platform Kit is organized in three layers:

1. **Platform core** — stable primitives every app and capability shares
2. **Platform infra** — shared connection helpers (Postgres, Redis, object storage)
3. **Capabilities** — domain features that plug into host apps

## Top-level layout

```txt
go-platform-kit/
  platform/       # shared kernel + infra helpers
  auth/           # authentication capability (runtime module)
  admin/          # admin UI schema compiler (stateless, no DB)
  migrations/     # baseline SQL for auth
  cmd/migrate/    # migration runner
  examples/       # reference integrations
  docs/           # architecture and guides
```

`auth/` and `admin/` sit side by side because they are **different kinds of capabilities**:

| Package | Role | Runtime deps |
|---------|------|--------------|
| `auth` | Login, sessions, RBAC, MFA, OAuth | Postgres, optional Redis |
| `admin` | Compile admin panel JSON from a contract | None |

Both follow the same **public surface rule**: host apps import only the top-level package (`auth`, `admin`), never `{capability}/internal`.

## Dependency rules

```
Host App
  → platform/config, platform/postgres, platform/redis, platform/httpx
  → auth, admin, (future capabilities)

Capability (auth, admin, ...)
  → platform/* only
  → never import another capability
  → never import {capability}/internal from outside the module subtree
```

## Platform packages

| Package | Role |
|---------|------|
| `platform/httpx` | Standard JSON responses, M00xxxx error codes, recovery, pagination, error mapper |
| `platform/log` | Logger interface; default noop |
| `platform/config` | Infra config loader; opt-in `FromEnv()`, `OpenInfra()` |
| `platform/postgres` | Open and ping shared pools |
| `platform/redis` | Open and ping shared clients |
| `platform/storage` | Cloudflare R2 ObjectStore |
| `platform/mail` | Mailer interface + SMTP sender (STARTTLS, context timeout) |
| `platform/health` | Health check helpers for Postgres and Redis |
| `platform/transaction` | Generic pgx transaction helper (`WithTx`, `TxFromCtx`) |
| `platform/clock` | Time abstraction for testability (`RealClock`, `FixedClock`) |
| `platform/id` | Pluggable ID generator (`UUIDGenerator`) |

Capabilities receive **opened** clients/pools from the host. They do not read environment variables directly.

### Shared primitives vs capability logic

| Concern | Platform | Capability (e.g. auth) |
|---------|----------|------------------------|
| JSON envelope + M00 codes | `platform/httpx` | handlers call `httpx.FailCode` |
| Error mapper chain | `platform/httpx.ErrorMapper` | auth registers `MapAuthError` |
| Panic recovery middleware | `platform/httpx.Recovery` | host mounts globally |
| SMTP send | `platform/mail.Mailer` | auth email use case builds verify/reset content |
| Postgres pool | `platform/postgres` | auth repos implement `ports` |

Mail content and token flows stay in auth; any future `notify` or billing module reuses `platform/mail` without importing auth.

## Capability template

When adding a new capability (e.g. `upload`, `notify`):

```txt
{capability}/
  doc.go           # Package documentation
  module.go        # New(ctx, opts...), public API
  option.go        # Functional options
  config.go        # Domain config + Validate
  mount.go         # HTTP route mounting (if applicable)
  internal/        # Implementation (see auth layout below)
```

Options should accept platform dependencies:

```go
upload.New(ctx,
    upload.WithObjectStore(store),
    upload.WithLogger(logger),
)
```

## Auth capability

### Public surface (headless)

| File | Purpose |
|------|---------|
| `open.go` | `Open`, `Auth` wiring |
| `api.go` | Use-case methods: `Login`, `Register`, `Refresh`, RBAC, MFA, … |
| `option.go` | Functional options |
| `config.go` | Domain configuration |
| `middleware.go` | `JWTAuth`, RBAC, team-token helpers |
| `errors.go` | `MapError`, `WriteError` for host handlers |
| `domain.go` | Minimal DTOs and errors |
| `mount_ref.go` | Reference routes (prefer host handlers) |
| `auth/gin` | Optional `MountAll` wrapper for prototypes |

Entry point — host owns HTTP:

```go
a, _ := auth.Open(ctx,
    auth.WithConfig(cfg),
    auth.WithPostgres(pg),
    auth.WithRedis(rdb),
)

r.POST("/v1/sign-in", func(c *gin.Context) {
    res, err := a.Login(ctx, email, password, auth.ClientMeta{IP: ip, UA: ua})
    if auth.WriteError(c, err, httpx.CodeAuthInvalidCredentials, 401) { return }
    httpx.Success(c, 200, "success", res, nil)
})

api.Use(a.JWTAuth())
```

Optional reference routes: `authgin.MountAll(a, r)` from `auth/gin`.

### Internal layout

Package names **match directory names** — one rule, no exceptions:

```txt
auth/internal/
  domain/       # entities + domain errors
  ports/        # repository and cache interfaces
  usecase/      # one subfolder per use case
    login/      # register, login, refresh
    session/    # session list/revoke
    rbac/       # roles and permissions
    mfa/        # TOTP
    oauth/      # Google OAuth2
    email/      # verify/reset flows
    admin/      # user admin (ban, list)
    audit/      # audit log writes
    cleanup/    # token/session cleanup jobs
  http/
    handler/    # Gin handlers (auth.go, session.go, …)
    middleware/ # JWT, RBAC, CORS, rate limit
  postgres/     # SQL repository implementations
  redis/        # permission cache + token denylist
  security/     # AES crypto + jwt/ subfolder
  validate/     # input validation, OAuth cookies
```

Flow: `http/handler` → `usecase/*` → `ports` ← `postgres` / `redis`.

Email delivery uses [platform/mail]; auth only owns verify/reset templates and token persistence.

Schema: `migrations/0001_baseline.up.sql`, applied via `cmd/migrate`.

## Admin capability

- Stateless JSON compiler: `admin.Compile`, `admin.MigrateV3`
- Four files at package root — intentionally minimal
- No database dependency; compiles admin panel schema from host-provided contract JSON

## How to add a new capability

1. Create new top-level package (e.g., `notify/`)
2. Follow auth pattern: `open.go` + `api.go` + `option.go` + `config.go` + `internal/`
3. Accept platform dependencies via functional options (`WithPostgres`, `WithLogger`, etc.)
4. Never import other capabilities
5. Add migration in `migrations/` if DB schema needed
6. Add example in `examples/`
7. Document in `docs/`

See [docs/DEPENDENCY_RULES.md](DEPENDENCY_RULES.md) for complete rules.

## Roadmap

| Capability | Status |
|------------|--------|
| auth | Implemented |
| admin | Implemented |
| platform/storage R2 | Implemented (Cloudflare R2 only) |
| platform/transaction | Implemented |
| platform/clock | Implemented |
| platform/id | Implemented |
| auth unit tests | login, MFA, Google OAuth, RBAC, session, email, admin, cleanup, middleware, handler |
| auth integration tests | register, login/logout, refresh, MFA, RBAC, Google OAuth (Postgres + mock Google) |
| postgres/redis integration | user/identity repos, JWT user cache (CI with DATABASE_URL + REDIS_URL) |
| upload / media | Planned |
| notify | Planned |
