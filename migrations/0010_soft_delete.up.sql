ALTER TABLE users
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_deleted_at
  ON users(deleted_at)
  WHERE deleted_at IS NOT NULL;

-- Safety net: prevent hard deletes on users table.
CREATE OR REPLACE FUNCTION prevent_user_hard_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Hard delete of users is not allowed. Use soft delete (set deleted_at) instead.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_user_hard_delete
  BEFORE DELETE ON users
  FOR EACH ROW
  EXECUTE FUNCTION prevent_user_hard_delete();
