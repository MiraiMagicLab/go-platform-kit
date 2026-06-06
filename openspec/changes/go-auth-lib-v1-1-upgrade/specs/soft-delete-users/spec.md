## ADDED Requirements

### Requirement: Soft Delete Users

The system SHALL mark users as deleted via a `deleted_at` timestamp rather than hard-deleting rows from the database. All standard read queries SHALL exclude soft-deleted users by default.

#### Scenario: Soft delete marks user and cascades

- **WHEN** an admin calls `DELETE /users/:id` (or the service method `SoftDeleteUser`)
- **THEN** the system SHALL set `users.deleted_at = NOW()`
- **AND** the system SHALL revoke all sessions for that user (`sessions.revoked_at = NOW()`)
- **AND** the system SHALL revoke all refresh tokens for that user
- **AND** the system SHALL increment `users.token_version` to invalidate all active access tokens

#### Scenario: Soft-deleted user cannot login

- **WHEN** a soft-deleted user attempts to login with valid credentials
- **THEN** the system SHALL return `auth.action.register_fail` (not reveal user existence)
- **AND** no tokens SHALL be issued

#### Scenario: GetByEmail excludes soft-deleted users

- **WHEN** a query looks up a user by email
- **THEN** the system SHALL add `WHERE deleted_at IS NULL` to the query
- **AND** a soft-deleted user SHALL not be found even with a matching email

#### Scenario: GetByID excludes soft-deleted users

- **WHEN** a query looks up a user by ID
- **THEN** the system SHALL add `WHERE deleted_at IS NULL` to the query
- **AND** a soft-deleted user SHALL not be returned

#### Scenario: ListUsers excludes soft-deleted by default

- **WHEN** an admin calls `GET /users`
- **THEN** the response SHALL NOT include soft-deleted users by default
- **AND** the system SHALL support `?include_deleted=true` to include them

#### Scenario: Hard delete is blocked by safety trigger

- **WHEN** a direct `DELETE FROM users` is issued at the database level
- **THEN** the system SHALL raise an exception via a `BEFORE DELETE` trigger
- **AND** the delete SHALL be rejected (safety net; application code MUST use the soft-delete method)
