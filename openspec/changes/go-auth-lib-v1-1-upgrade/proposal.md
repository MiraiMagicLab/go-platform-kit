## Why

go-auth-lib v1.0 covers the essentials (JWT auth, RBAC, MFA, OAuth, email verification, refresh token rotation, audit logging) but has gaps that limit its fitness for production at scale: missing `updated_at` triggers, weak email validation, no brute-force protection, an OAuth state cookie vulnerable to CSRF, an MFA disable flow with no password/code verification, permission cache invalidation gaps, audit log that will outgrow a single table, and a sessions model backed purely by refresh token chains rather than a proper session entity. Upgrading to v1.1 closes these gaps and adds a dedicated sessions table, CITEXT email uniqueness, soft-delete, and account lock for brute-force defense.

## What Changes

**Schema Additions (9 migrations, all backward-compatible):**

- `updated_at` auto-trigger on all tables that have the column
- `CITEXT` extension for case-insensitive email uniqueness
- Composite index on `email_action_tokens(user_id, action_type)`
- Unique partial index on `user_mfa_recovery_codes(code_hash)` for unused codes
- `device_name TEXT NULL` on `refresh_tokens` for parsed user-agent display
- New `sessions` table as authoritative session entity (refresh tokens reference it)
- `failed_login_count` and `locked_until` columns on `users` for account lock
- `deleted_at` column on `users` for soft-delete
- Partitioned `audit_logs` table by month (pg_partman or manual range partitions)

**Code Improvements (zero breaking API changes):**

- Replace weak `strings.Contains(email, "@")` with `net/mail.ParseAddress` for email validation
- OAuth state cookie: add `SameSite=Lax`, explicit `Path`, configurable `Secure`
- MFA disable: require current password OR active MFA code before allowing disable
- Admin role bypass: users with `admin` role skip RBAC permission checks
- `AssignPermissionsToRole`: invalidate permission cache for all users in that role
- `InMemoryRateLimiter`: periodic cleanup of expired entries to prevent memory leak
- RBAC batch insert: fully consume pgx batch results before Close to avoid protocol error
- `ForgotPassword`: constant-time hint (configurable sleep) to mitigate user enumeration via timing

**New Capabilities:**

- Sessions table with `device_name`, `last_seen_at`, supporting per-device revoke and "logout all except current"
- Account lock after N failed login attempts with configurable lock duration
- Soft-delete users (no hard delete; all queries exclude deleted users)
- Admin role bypasses permission checks (admin role always passes `RequirePermission`)

## Capabilities

### New Capabilities

- `sessions-table`: Dedicated `sessions` table as authoritative login-device entity, replacing refresh-token-chain-as-session pattern. Supports per-device metadata, last-seen tracking, and efficient revoke-all-except-current.
- `account-lock`: Brute-force protection via `failed_login_count` and `locked_until` columns on `users`. Configurable threshold and lock duration. Resets on successful login.
- `soft-delete-users`: Users are soft-deleted (`deleted_at` timestamp) rather than hard-deleted. All read queries exclude deleted users automatically. Cascade soft-delete to related records via application layer.
- `admin-bypass`: Users assigned the `admin` role bypass all RBAC permission checks (`RequirePermission` always passes for admins). Reduces boilerplate for internal tools and admin dashboards.
- `oauth-cookie-hardening`: OAuth CSRF state cookie hardened with `SameSite=Lax`, explicit `Path`, and `Secure` flag (set by host app). Prevents state leakage across origins.
- `email-validation`: Email format validated via `net/mail.ParseAddress` plus length and format sanity checks. Rejects malformed addresses at registration.
- `mfa-disable-verify`: MFA disable requires either the user's current password or a valid active MFA code. Prevents token-theft disable attacks.

### Modified Capabilities

- `auth-service`: No spec change — implementation improvements only (account lock integration, constant-time forgot password hint).
- `mfa-service`: No spec change — implementation improvements only (admin bypass, MFA disable verification).
- `rbac-service`: No spec change — implementation improvements only (permission cache invalidation on role-permission assignment).
- `session-management`: No spec change — implementation improvements only (sessions table as backing store, `device_name`).

## Impact

**Code:** ~25 files modified, 2 new files (`sessions_repo.go`, `oauth_cookie.go`), 9 migration files.

**APIs:** All existing API endpoints unchanged. New optional config fields added to `authkit.Config`.

**Database:** 9 migrations (additive), all `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`. No breaking changes to existing rows. Sessions table is new. Audit log partition conversion is large but non-blocking if using pg_partman.

**Dependencies:** No new external dependencies. Existing deps unchanged.

**Deploy risk:** Low. All migrations are additive. Sessions table and audit partition require backfill scripts but no downtime.

**Testing:** Existing tests pass without modification. New test coverage for account lock flow, MFA disable verification, email validation edge cases, sessions table CRUD, admin bypass, and permission cache invalidation.
