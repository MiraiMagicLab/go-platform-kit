ALTER TABLE users
  ADD COLUMN IF NOT EXISTS failed_login_count INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_locked_until
  ON users(locked_until)
  WHERE locked_until IS NOT NULL;
