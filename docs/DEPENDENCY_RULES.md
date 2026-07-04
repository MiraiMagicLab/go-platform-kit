# Dependency Rules

## Layer hierarchy

```
Host App
  → platform/* (stable kernel)
  → auth, admin, (future capabilities)

Capability (auth, admin, ...)
  → platform/* only
  → never import another capability
  → never import {capability}/internal from outside

platform/*
  → no auth/admin imports
  → no business domain imports
  → stdlib + well-known libraries only
```

## Rules

1. **platform/* is the stable kernel.** No business logic, no capability imports.

2. **Capabilities are independent.** Auth does not import admin. Admin does not import auth.

3. **Host apps import top-level packages only.** Never import `auth/internal/` or `admin/internal/`.

4. **Capabilities receive opened clients.** They do not read environment variables directly. Host opens Postgres/Redis and passes them via functional options.

5. **Platform packages accept interfaces, return concrete types.** This allows testability without over-abstracting.

## Forbidden

- `platform/httpx` importing `auth/`
- `auth/` importing `admin/`
- Host app importing `auth/internal/postgres/`
- Any circular dependency between packages

## Adding a new capability

Follow the auth pattern:

```
{capability}/
  doc.go           # Package documentation
  open.go          # New/Open entry point
  api.go           # Public use-case methods
  option.go        # Functional options
  config.go        # Domain configuration
  domain.go        # DTOs and errors
  middleware.go     # HTTP middleware (if applicable)
  errors.go        # Error mapping
  internal/        # Implementation (hidden from host)
    domain/
    ports/
    usecase/
    http/
    postgres/
    redis/
  migrations/      # Schema (if applicable)
  docs/            # Capability-specific docs
```
