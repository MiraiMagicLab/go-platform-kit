## Context

go-auth-lib v1.0 is a production-ready embedded auth library for Go/Gin with Postgres (optional Redis). Current stack: JWT auth, dynamic RBAC, TOTP MFA, OAuth2 (Google/Facebook), email verification, refresh token rotation with replay detection, audit logging. The library is imported as a private Go module by host applications that embed auth routes into their Gin router.

This v1.1 upgrade addresses 13 schema gaps and 7 code-level issues identified during code review. All changes are backward-compatible — no existing APIs are modified, no existing DB columns are dropped, no existing behavior is removed.

## Goals / Non-Goals

**Goals:**

- Add `updated_at` auto-trigger across all relevant tables
- Switch email to `CITEXT` for case-insensitive uniqueness
- Add composite index on `email_action_tokens(user_id, action_type)`
- Add unique partial index on `user_mfa_recovery_codes(code_hash)` for unused codes
- Add `device_name` to `refresh_tokens` for parsed user-agent display
- Introduce `sessions` table as authoritative login-device entity
- Add account lock (`failed_login_count`, `locked_until`) for brute-force protection
- Add soft-delete (`deleted_at`) for users
- Partition `audit_logs` by month
- Fix email validation to use `net/mail.ParseAddress`
- Harden OAuth state cookie with `SameSite=Lax`
- Require password or MFA code to disable MFA
- Admin role bypasses all `RequirePermission` checks
- Invalidate permission cache when role permissions change
- Fix `InMemoryRateLimiter` memory leak
- Fix RBAC batch pgx protocol consumption
- Add constant-time hint to `ForgotPassword`

**Non-Goals:**

- Breaking changes to existing API contracts (all `AuthEndpoints`, `RBACEndpoints`, etc. unchanged)
- Dropping any existing database columns
- Adding new external dependencies
- Migrating to a different auth pattern (e.g., PASETO, OAuth2 token introspection)
- Implementing device fingerprinting
- Full OIDC support (beyond current OAuth2)
- Multi-tenancy beyond the existing TeamToken model

## Decisions

### D1: Sessions Table — New Table, Not Refactor

**Decision:** Introduce a new `sessions` table as the authoritative entity for login sessions, with `refresh_tokens` referencing `sessions.id`.

**Rationale:** The current model uses `refresh_tokens.session_id` as a UUID cluster-key to group refresh token chains per login device. This works but forces `ListActiveSessions` to use `DISTINCT ON (session_id)` over the refresh token table — a SQL pattern that works but scales poorly as the refresh token table grows (rotation creates a new row per refresh). A dedicated `sessions` table has one row per device, updated on each refresh via `last_seen_at`, making session listing O(1) per user rather than O(n) over token history.

**Alternatives considered:**
- *Keep refresh-token-chain as session*: Simpler, no new table. But `ListActiveSessions` degrades as tokens rotate. Rejected.
- *Separate sessions service + table*: More complex, separates session logic from token logic. Not needed at this scale.

**Backfill:** A one-time migration script creates session rows from distinct `(user_id, session_id)` groups in existing `refresh_tokens` data.

---

### D2: Account Lock — Fields on `users`, Not Redis

**Decision:** Store `failed_login_count` and `locked_until` as columns on the `users` table rather than Redis counters.

**Rationale:** Simpler consistency model. Locked accounts are rare (security feature), so DB write per failed login is acceptable. Redis would add failure surface (Redis down = no lock enforcement), and Go-auth-lib already has Redis as optional. Keeping it on `users` makes the lock immediately visible to all auth checks via the existing `GetByID` call in `JWTAuth` middleware — no additional Redis round-trip.

**Threshold and duration** are configured via `authkit.Config.MaxFailedLoginAttempts` (default 5) and `authkit.Config.AccountLockDuration` (default 15 minutes), matching common practice.

**Alternatives considered:**
- *Redis counter per user*: Faster but requires Redis. Adds failure mode. Rejected for simplicity.
- *Separate `account_locks` table*: Over-engineered for this use case.

---

### D3: Admin Bypass — In-Middleware Check

**Decision:** `RequirePermission` checks for `admin` role in addition to the requested permission.

**Rationale:** The most common pattern in internal tools is "admins can do everything." Hardcoding this in the middleware avoids host applications needing to add `admin` to every permission list. It's a single check, non-breaking, and easy to disable via config flag `AdminBypassPermission bool`.

**Alternatives considered:**
- *Service-layer bypass*: Would require changes to every service method. Too invasive. Rejected.
- *Separate `is_admin` column on `users`*: Adds a new column and logic path. `admin` role check reuses existing RBAC infrastructure.

---

### D4: Audit Log Partitioning — Monthly Range with pg_partman

**Decision:** Partition `audit_logs` by `RANGE (created_at)` using monthly partitions, managed by `pg_partman`.

**Rationale:** Audit logs accumulate indefinitely and can reach millions of rows in active systems. Monthly partitions allow `DROP` of old partitions without `DELETE`, and per-partition indexes that stay small. `pg_partman` automates partition creation/deletion based on retention policy (`audit_log_retention_days` config), eliminating manual cron jobs.

**Alternatives considered:**
- *Single table, no partition*: Fine for <1M rows. Not safe for production at scale. Rejected.
- *Manual partition creation cron*: Works but adds operational burden. pg_partman is standard in Postgres shops.

---

### D5: OAuth State Cookie — SameSite=Lax, Configurable Secure

**Decision:** Set `SameSite=Lax` on the OAuth state cookie. `Secure` flag remains false by default (dev-friendly), host app sets it via config or environment.

**Rationale:** `SameSite=Lax` prevents CSRF in the OAuth state validation flow while allowing the cookie to follow navigations from email links (common in password-reset + OAuth combined flows). `SameSite=Strict` would break that UX. `Secure` should be `true` in production; leaving it `false` by default avoids breaking local dev setups.

**Host app config:** `cfg.OAuthCookieSecure bool` (default `false`).

---

### D6: MFA Disable — Password or MFA Code Verification

**Decision:** `POST /mfa/disable` requires either valid `password` (current password) OR valid `code` (current MFA TOTP/recovery code) in the request body.

**Rationale:** The current implementation allows any authenticated user to disable their own MFA with only a valid access token — a stolen token enables MFA disable without knowing the account credentials. Adding a second factor (password or current MFA code) closes this attack vector. Configurable via `cfg.RequirePasswordForMFADisable bool` (default `true`) to allow disabling in dev/test environments.

**Alternatives considered:**
- *Require both password AND MFA code*: Too friction-heavy for legitimate users. Rejected.
- *TOTP-only (no password option)*: Fails for users who lose their authenticator and have no recovery codes. Rejected.

---

### D7: Email Validation — `net/mail.ParseAddress` + Length Checks

**Decision:** Replace `strings.Contains(email, "@")` with `mail.ParseAddress` plus basic format sanity checks (local part ≤64, domain ≤255 per RFC 5321).

**Rationale:** `mail.ParseAddress` correctly handles quoted strings, display names, and comments. Combined with length checks it covers the common attack surface without adding a regex dependency. For strict validation, host apps can provide a custom `Config.EmailValidator` hook.

---

### D8: Soft Delete — `deleted_at` Column, No Trigger Cascade

**Decision:** Add `deleted_at TIMESTAMPTZ NULL` to `users`. All `SELECT` queries exclude rows where `deleted_at IS NOT NULL`. No trigger cascade — soft-delete of related records (sessions, refresh tokens) handled in application layer.

**Rationale:** `ON DELETE CASCADE` on FK relationships means hard-deleting a user cascades to all related rows automatically. Soft-delete requires explicit handling: `SoftDeleteUser` marks `deleted_at`, then iterates related repos to set `revoked_at` on sessions and refresh tokens. Simpler than reversing FK cascades and avoids trigger complexity.

**Consistent reads:** `GetByEmail` and `GetByID` always add `WHERE deleted_at IS NULL`. No separate "include deleted" flag by default.

---

### D9: Permission Cache Invalidation — Invalidate All Users in Role

**Decision:** When permissions are assigned to a role (`AssignPermissionsToRole`), invalidate the permission cache for **all users** who have that role.

**Rationale:** Permission changes are infrequent (admin action) so invalidating the entire role's user set is acceptable. The current code does nothing on `AssignPermissionsToRole` — permission changes go unnoticed until the cache TTL expires (30s default). The cache key is `perm:user:{userID}`.

**Implementation:** `RBACService.AssignPermissionsToRole` calls `ListUserIDsByRole(roleID)` (new repo method) then loops over each userID calling `s.cache.Del(ctx, userPermCacheKey(uid))`.

---

### D10: Migration Order — Additive, No Breaking Changes

**Decision:** All 9 migrations are additive (`ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, new table). Zero `DROP` or `ALTER ... TYPE`. Code changes are behind feature flags where needed.

**Rationale:** This allows host applications to update the library without running migrations simultaneously. Code that references new columns checks for their existence or uses Go zero-values for columns not yet added (handled gracefully by `IF NOT EXISTS` semantics).

## Risks / Trade-offs

- **[R1] Audit partition migration blocks writes** → Use `pg_partman` with `partition_maintenance = off` during conversion, or run during maintenance window. Manual partitions can be created `CONCURRENTLY` to avoid lock.
- **[R2] Sessions table backfill on large token tables** → Backfill script uses `INSERT ... ON CONFLICT DO NOTHING` in batches of 1000, with no lock on the source table. Safe for production.
- **[R3] CITEXT migration on large user table** → `ALTER TABLE ... ALTER COLUMN ... TYPE` acquires `ACCESS EXCLUSIVE` lock. On large tables use `CREATE EXTENSION` + `ALTER COLUMN TYPE` with `SET lock_timeout = '2s'` to fail fast rather than wait indefinitely.
- **[R4] Soft delete + hard delete FK cascades** → If host app ever calls `DELETE FROM users`, PostgreSQL hard-deletes all related rows. Document that host apps must use the `SoftDeleteUser` service method. Add a DB trigger as a safety net: `BEFORE DELETE ON users` → raise exception.
- **[R5] Admin bypass enables privilege escalation** → If a user somehow gets the `admin` role assigned, they bypass all permission checks. Mitigated by requiring `rbac.manage` permission to assign roles (already the case). Admin role assignment should be audited.
- **[R6] InMemoryRateLimiter cleanup under high concurrency** → Cleanup runs at most once per minute, holding the mutex. Acceptable for a rate limiter. If contention is observed, reduce cleanup frequency.

## Migration Plan

### Phase 1: Schema Safety (zero-risk, backward-compatible)

1. Run `0003_updated_at_trigger.up.sql` — creates trigger on `users.updated_at`
2. Run `0004_citext_email.up.sql` — creates citext extension, alters email column
3. Run `0005_email_tokens_composite_index.up.sql` — adds composite index
4. Run `0006_recovery_code_unique.up.sql` — adds unique partial index
5. Deploy code: remove explicit `updated_at = NOW()` from `user_repo.go`

### Phase 2: New Capabilities

6. Run `0007_refresh_token_device_name.up.sql` — adds `device_name` column
7. Run `0008_sessions_table.up.sql` + backfill script — new sessions table + data migration
8. Deploy sessions code — wire `SessionsRepo`, update `SessionService`
9. Run `0009_account_lock.up.sql` — adds lock columns
10. Deploy account lock code

### Phase 3: Architecture

11. Run `0010_soft_delete.up.sql` — adds `deleted_at` column + safety trigger
12. Deploy soft delete code
13. Add admin bypass to `RequirePermission` middleware
14. Fix MFA disable, email validation, rate limiter, RBAC batch

### Phase 4: Scale (optional, depends on volume)

15. Run `0011_audit_partition.up.sql` — convert `audit_logs` to partitioned table
16. Alternatively: install `pg_partman`, configure retention policy, skip manual partition migration

### Rollback

Each migration is idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). Rollback scripts provided for each. Code changes are additive feature flags — disabling the flag returns to pre-v1.1 behavior.

## Open Questions

- **[Q1] Account lock threshold and duration defaults?** Suggest 5 failed attempts / 15 minutes. Confirm with user.
- **[Q2] Audit log partition retention?** Suggest 90 days for full logs, with hot/cold separation. Confirm.
- **[Q3] Soft delete — should `ListUsers` (admin RBAC endpoint) include deleted users?** Suggest `include_deleted` query param defaulting to `false`. Confirm.
- **[Q4] Admin bypass — default enabled or disabled?** Suggest `true` (enabled) since it matches common expectation. Configurable via `AdminBypassPermission: false`.
- **[Q5] Sessions table — should we migrate existing refresh token session_id chains?** Yes, backfill creates one session row per `(user_id, session_id)` group.
