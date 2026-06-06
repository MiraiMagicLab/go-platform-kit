## ADDED Requirements

### Requirement: Admin Role Bypasses Permission Checks

The system SHALL allow users assigned the `admin` role to bypass all RBAC permission checks. When `RequirePermission` middleware evaluates a user's permissions, if the user has the `admin` role, the request SHALL pass without checking the specific permission string.

#### Scenario: Admin passes any permission check

- **WHEN** a user with the `admin` role calls `GET /api/vocab` protected by `RequirePermission("vocab.create")`
- **THEN** the system SHALL allow the request to proceed
- **AND** the system SHALL NOT query or check for the `vocab.create` permission

#### Scenario: Non-admin user is checked normally

- **WHEN** a user without the `admin` role calls `GET /api/vocab` protected by `RequirePermission("vocab.create")`
- **THEN** the system SHALL query the user's permissions from the database
- **AND** the request SHALL proceed only if `vocab.create` is in the user's permission set
- **OTHERWISE** the system SHALL return HTTP 403 `auth.forbidden`

#### Scenario: Admin bypass is configurable

- **WHEN** `authkit.Config.AdminBypassPermission` is set to `false`
- **THEN** the admin role SHALL NOT bypass permission checks
- **AND** all users SHALL be evaluated against the standard permission set
- **DEFAULT** value SHALL be `true`

#### Scenario: Admin bypass applies to all RequirePermission instances

- **WHEN** `RequirePermission` is used anywhere in the router (auth routes or host app routes)
- **THEN** the admin bypass SHALL apply uniformly
- **AND** there SHALL be no way to opt out per-endpoint (use `AdminBypassPermission: false` globally if needed)
