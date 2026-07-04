# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Breaking Changes
- `platform/config`: Removed `Auth` field from `Config`. Auth config is now managed by `auth.Config` directly.
- `platform/httpx`: Moved error codes to `platform/errors`. Moved pagination to `platform/pagination`.
- `platform/httpx`: Removed `CodeSuccess`, `CodeCreated` etc. Use `platform/errors.CodeXxx` instead.
- Removed `sql/schema.sql`. Use `migrations/` as single source of truth.

### Added
- `platform/errors/` — Error codes, error mapper, message registry (split from httpx)
- `platform/pagination/` — Limit/offset and cursor pagination helpers (split from httpx)
- `platform/transaction/` — Generic pgx transaction helper
- `platform/clock/` — Time abstraction for testing
- `platform/id/` — Pluggable ID generator
- `docs/DEPENDENCY_RULES.md` — Explicit import rules
- `docs/VERSIONING.md` — Semantic versioning policy
- `docs/MIGRATIONS.md` — Migration guide
- `docs/AUTH.md` — Auth capability documentation
- `docs/HTTP_CONVENTIONS.md` — HTTP response conventions
- `examples/minimal-api/` — Simplest API example
- `examples/auth-only/` — Auth wiring example
- `CHANGELOG.md`

### Changed
- `docs/ARCHITECTURE.md` — Updated with new package layout
- `README.md` — Updated package tables

### Removed
- `platform/config.Auth` — Auth config moved to auth capability
- `sql/schema.sql` — Duplicate of migrations
