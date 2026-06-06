ALTER TABLE refresh_tokens
  ADD COLUMN IF NOT EXISTS device_name TEXT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_refresh_tokens_device_name
  ON refresh_tokens(user_id, device_name)
  WHERE device_name IS NOT NULL;
