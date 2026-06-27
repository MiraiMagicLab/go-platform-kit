# Architecture

Go Platform Kit is organized in three layers:

1. **Platform core** — stable primitives every app and capability shares
2. **Platform infra** — shared connection helpers (Postgres, Redis, object storage)
3. **Capabilities** — domain features that plug into host apps

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
| `platform/httpx` | Standard JSON responses and M00xxxx codes |
| `platform/log` | Logger interface; default noop |
| `platform/config` | Infra config loader; opt-in `FromEnv()` |
| `platform/postgres` | Open and ping shared pools |
| `platform/redis` | Open and ping shared clients |
| `platform/storage` | ObjectStore interface for uploads |

Capabilities receive **opened** clients/pools from the host. They do not read environment variables directly.

## Capability template

When adding a new capability (e.g. `upload`, `notify`):

```txt
{capability}/
  doc.go           # Package documentation
  module.go        # New(ctx, opts...), public API
  option.go        # Functional options
  config.go        # Domain config + Validate
  internal/        # Handlers, services, provider-specific code
```

Options should accept platform dependencies:

```go
upload.New(ctx,
    upload.WithObjectStore(store),
    upload.WithLogger(logger),
)
```

## Auth capability

- Public entry: `auth.New`, `auth.Module.MountAll`, middleware helpers
- Internal layout: `service` (use cases), `postgres` (SQL), `gin` (HTTP)
- Schema: `migrations/`, applied via `cmd/migrate`

## Admin capability

- Stateless JSON compiler: `admin.Compile`, `admin.MigrateV3`
- No database dependency

## Roadmap

| Capability | Status |
|------------|--------|
| auth | Implemented |
| admin | Implemented |
| platform/storage R2 | Interface stub |
| upload / media | Planned |
| notify | Planned |
