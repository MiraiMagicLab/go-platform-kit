CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_user_mfa_recovery_code_hash_uniq
  ON user_mfa_recovery_codes(code_hash)
  WHERE used_at IS NULL;
