## 1. Schema Migrations

- [x] 1.1 Create `migrations/0003_updated_at_trigger.up.sql` — trigger function + trigger on `users`
- [x] 1.2 Create `migrations/0003_updated_at_trigger.down.sql` — drop trigger and function
- [x] 1.3 Create `migrations/0004_citext_email.up.sql` — create citext extension, alter email column type, drop old unique constraint
- [x] 1.4 Create `migrations/0004_citext_email.down.sql` — alter email back to TEXT
- [x] 1.5 Create `migrations/0005_email_tokens_composite_index.up.sql` — composite index on `(user_id, action_type)`
- [x] 1.6 Create `migrations/0005_email_tokens_composite_index.down.sql` — drop index
- [x] 1.7 Create `migrations/0006_recovery_code_unique.up.sql` — unique partial index on `code_hash WHERE used_at IS NULL`
- [x] 1.8 Create `migrations/0006_recovery_code_unique.down.sql` — drop index
- [x] 1.9 Create `migrations/0007_refresh_token_device_name.up.sql` — add `device_name TEXT NULL` column
- [x] 1.10 Create `migrations/0007_refresh_token_device_name.down.sql` — drop column
- [x] 1.11 Create `migrations/0008_sessions_table.up.sql` — new `sessions` table with all columns and indexes
- [x] 1.12 Create `migrations/0008_sessions_table.down.sql` — drop sessions table
- [x] 1.13 Create `migrations/0008_sessions_backfill.sql` — backfill script: one session row per `(user_id, session_id)` from `refresh_tokens`
- [x] 1.14 Create `migrations/0009_account_lock.up.sql` — add `failed_login_count INT`, `locked_until TIMESTAMPTZ` to `users`
- [x] 1.15 Create `migrations/0009_account_lock.down.sql` — drop columns
- [x] 1.16 Create `migrations/0010_soft_delete.up.sql` — add `deleted_at TIMESTAMPTZ` to `users` + safety before-delete trigger
- [x] 1.17 Create `migrations/0010_soft_delete.down.sql` — drop column and trigger
- [x] 1.18 Create `migrations/0011_audit_partition.up.sql` — partitioned `audit_logs` by month (or configure pg_partman)
- [x] 1.19 Update `sql/schema.sql` — mirror all 9 migration changes into the single-file schema

## 2. New Files

- [x] 2.1 Create `internal/repositories/postgres/sessions_repo.go` — SessionsRepo with Create, ListActive, Touch, Revoke, RevokeAllExcept, Backfill methods
- [x] 2.2 Create `pkg/authkit/oauth_cookie.go` — OAuth state cookie helpers (SameSite, Secure, Path, HttpOnly)
- [x] 2.3 Create `internal/utils/useragent.go` (or in services) — DeviceNameFromUA parser function

## 3. Repository Layer

- [x] 3.1 Update `internal/repositories/postgres/common.go` — add Sessions to Repos struct and NewRepos
- [x] 3.2 Update `internal/repositories/postgres/types.go` — add `failed_login_count`, `locked_until`, `deleted_at` to UserDTO; add `device_name` to RefreshTokenDTO; add `SessionRow` struct
- [x] 3.3 Update `internal/repositories/postgres/user_repo.go` — remove explicit `updated_at = NOW()` from SetPassword, SetEmailVerified, SetBan; add IncrementFailedLogin, ResetFailedLogin, SetLock; add SoftDelete; update GetByEmail/GetByID/ListUsers to filter `deleted_at IS NULL`
- [x] 3.4 Update `internal/repositories/postgres/refresh_token_repo.go` — add deviceName param to Create and Rotate; update INSERT statements to include device_name
- [x] 3.5 Update `internal/repositories/postgres/rbac_repo.go` — fix pgx batch close to consume all results; add ListUserIDsByRole for cache invalidation

## 4. Service Layer

- [x] 4.1 Update `internal/services/auth.go` — account lock check in Login (check locked_until before password verify, increment failed_login_count on fail, set lock on threshold); reset failed count on success; add ErrAccountLocked error type; add soft delete check in Login
- [x] 4.2 Update `internal/services/rbac.go` — AssignPermissionsToRole: invalidate permission cache for all users in role (call ListUserIDsByRole, loop cache.Del)
- [x] 4.3 Update `internal/services/session.go` — wire SessionsRepo; update List/RevokeSession/RevokeOtherSessions to use sessions table; add TouchSession on refresh
- [x] 4.4 Update `internal/services/email.go` — add constant-time hint in ForgotPassword (configurable sleep)

## 5. Controller Layer

- [x] 5.1 Update `internal/controllers/auth.go` — replace `strings.Contains(email, "@")` with `net/mail.ParseAddress` + length checks in Register; handle ErrAccountLocked in Login
- [x] 5.2 Update `internal/controllers/mfa.go` — update Disable to require password or MFA code (bind new req struct, verify before disable); update Setup to use email as account name (currently uses UUID)
- [x] 5.3 Update `internal/controllers/oauth.go` — use new OAuth cookie helpers (SameSite, Path, HttpOnly, Secure flag); add DeviceName parsing from UA
- [x] 5.4 Update `internal/controllers/rbac.go` — add DeleteUser handler (soft delete); add soft delete audit log

## 6. Middleware Layer

- [x] 6.1 Update `internal/middleware/permission.go` — add admin role bypass check (if user has admin role, skip permission check); respect AdminBypassPermission config flag
- [x] 6.2 Update `internal/middleware/auth.go` — add locked_until check in JWTAuth (after token_version check); abort with account locked error
- [x] 6.3 Update `internal/middleware/rate_limit.go` — add periodic cleanup of expired InMemoryRateLimiter entries (lastCleanup field + cleanupLocked method)

## 7. Config and Module Wiring

- [x] 7.1 Update `pkg/authkit/module.go` — add Config fields: MaxFailedLoginAttempts (default 5), AccountLockDuration (default 15m), RequirePasswordForMFADisable (default true), AdminBypassPermission (default true), OAuthCookieSecure (default false), EmailValidator func (optional)
- [x] 7.2 Update `pkg/authkit/module.go` — wire SessionsRepo into SessionService; add Sessions to New() constructor
- [x] 7.3 Update `pkg/authkit/module.go` — update MountAuth/MountWithOptions to pass device name parser to service layer

## 8. Models

- [x] 8.1 Update `internal/models/models.go` — add FailedLoginCount, LockedUntil, DeletedAt fields to User struct

## 9. Response Codes

- [x] 9.1 Update `pkg/response/codes.go` — add CodeAuthAccountLocked and default message; add CodeAuthSoftDeleted if needed

## 10. Integration and Polish

- [x] 10.1 Update `examples/embedded/main.go` — add new config fields (MaxFailedLoginAttempts, AccountLockDuration, AdminBypassPermission, etc.)
- [x] 10.2 Update `README.md` — document new v1.1 features: sessions table, account lock, soft delete, admin bypass, OAuth cookie hardening, MFA disable verification, email validation, audit partitioning
- [x] 10.3 Add unit tests for account lock flow (service layer)
- [x] 10.4 Add unit tests for MFA disable verification
- [x] 10.5 Add unit tests for email validation edge cases
- [x] 10.6 Add unit tests for admin bypass middleware
- [x] 10.7 Add unit tests for permission cache invalidation on AssignPermissionsToRole
- [x] 10.8 Verify all existing tests pass (`go test ./...`)
- [x] 10.9 Run `go mod tidy` and verify go.sum is clean
