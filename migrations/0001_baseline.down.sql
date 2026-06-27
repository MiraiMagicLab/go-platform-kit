-- Rollback baseline schema v1.0

DROP TRIGGER IF EXISTS trg_prevent_user_hard_delete ON users;
DROP FUNCTION IF EXISTS prevent_user_hard_delete();
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS email_action_tokens;
DROP TABLE IF EXISTS user_mfa_recovery_codes;
DROP TABLE IF EXISTS user_mfa;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
