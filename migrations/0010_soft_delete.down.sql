DROP TRIGGER IF EXISTS trg_prevent_user_hard_delete ON users;
DROP FUNCTION IF EXISTS prevent_user_hard_delete();
ALTER TABLE users
  DROP COLUMN IF EXISTS deleted_at;
