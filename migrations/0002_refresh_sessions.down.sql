drop index if exists idx_refresh_tokens_session_active;
drop index if exists idx_refresh_tokens_user_session;

alter table refresh_tokens drop column if exists last_used_at;
alter table refresh_tokens drop column if exists user_agent;
alter table refresh_tokens drop column if exists ip_address;
alter table refresh_tokens drop column if exists session_id;
