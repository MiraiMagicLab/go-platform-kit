-- Session identity for refresh-token chains (login devices / browsers).
alter table refresh_tokens
  add column if not exists session_id uuid;

update refresh_tokens set session_id = gen_random_uuid() where session_id is null;

alter table refresh_tokens
  alter column session_id set not null;

alter table refresh_tokens
  add column if not exists ip_address text,
  add column if not exists user_agent text,
  add column if not exists last_used_at timestamptz not null default now();

create index if not exists idx_refresh_tokens_user_session on refresh_tokens(user_id, session_id);
create index if not exists idx_refresh_tokens_session_active on refresh_tokens(user_id, session_id)
  where revoked_at is null;
