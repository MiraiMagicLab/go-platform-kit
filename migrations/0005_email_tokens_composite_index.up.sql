CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_email_action_tokens_user_action
  ON email_action_tokens(user_id, action_type);
