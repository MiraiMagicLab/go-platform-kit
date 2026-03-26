-- Enable UUID generation (pgcrypto provides gen_random_uuid()).
create extension if not exists pgcrypto;

-- USERS
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  password_hash text not null,
  password_login_enabled boolean not null default true,
  token_version int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_users_email on users(email);

-- ROLES
create table if not exists roles (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now()
);

-- PERMISSIONS
create table if not exists permissions (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now()
);

-- USER_ROLES (many-to-many)
create table if not exists user_roles (
  user_id uuid not null references users(id) on delete cascade,
  role_id uuid not null references roles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, role_id)
);

create index if not exists idx_user_roles_user_id on user_roles(user_id);
create index if not exists idx_user_roles_role_id on user_roles(role_id);

-- ROLE_PERMISSIONS (many-to-many)
create table if not exists role_permissions (
  role_id uuid not null references roles(id) on delete cascade,
  permission_id uuid not null references permissions(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (role_id, permission_id)
);

create index if not exists idx_role_permissions_role_id on role_permissions(role_id);
create index if not exists idx_role_permissions_permission_id on role_permissions(permission_id);

-- REFRESH TOKENS (rotation + revocation)
create table if not exists refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz null,
  revoked_reason text null,
  replaced_by uuid null references refresh_tokens(id),
  created_at timestamptz not null default now()
);

create index if not exists idx_refresh_tokens_user_id on refresh_tokens(user_id);
create index if not exists idx_refresh_tokens_token_hash on refresh_tokens(token_hash);
create index if not exists idx_refresh_tokens_expires_at on refresh_tokens(expires_at);

-- OAUTH / SOCIAL IDENTITIES
create table if not exists user_identities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  provider text not null, -- e.g. 'google', 'facebook'
  provider_subject text not null, -- provider user id (sub)
  email text null,
  created_at timestamptz not null default now(),
  unique (provider, provider_subject),
  unique (user_id, provider)
);

create index if not exists idx_user_identities_user_id on user_identities(user_id);

-- MFA (TOTP)
create table if not exists user_mfa (
  user_id uuid primary key references users(id) on delete cascade,
  totp_secret text not null,
  enabled boolean not null default false,
  enabled_at timestamptz null,
  created_at timestamptz not null default now()
);

create table if not exists user_mfa_recovery_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  code_hash text not null,
  used_at timestamptz null,
  created_at timestamptz not null default now()
);

create index if not exists idx_user_mfa_recovery_user_id on user_mfa_recovery_codes(user_id);
create index if not exists idx_user_mfa_recovery_code_hash on user_mfa_recovery_codes(code_hash);

-- Seed baseline roles + permissions (idempotent)
insert into roles (name) values ('admin') on conflict (name) do nothing;
insert into roles (name) values ('user') on conflict (name) do nothing;

insert into permissions (name) values
  ('rbac.manage')
on conflict (name) do nothing;

-- Give admin all existing permissions
insert into role_permissions (role_id, permission_id)
select r.id, p.id
from roles r
join permissions p on true
where r.name = 'admin'
on conflict do nothing;

