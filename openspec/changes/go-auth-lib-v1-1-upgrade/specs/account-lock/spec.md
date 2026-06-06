## ADDED Requirements

### Requirement: Account Lock After Failed Login Attempts

The system SHALL lock a user account after a configurable number of consecutive failed login attempts, preventing further authentication until the lock expires.

#### Scenario: Account locks after N failed attempts

- **WHEN** a user fails `MaxFailedLoginAttempts` (default 5) consecutive login attempts within the lock window
- **THEN** the system SHALL set `users.locked_until = NOW() + AccountLockDuration`
- **AND** the system SHALL reset `users.failed_login_count` to 0
- **AND** subsequent login attempts SHALL return `auth.account.locked` with `locked_until` in the response

#### Scenario: Successful login resets failed counter

- **WHEN** a user successfully authenticates with valid credentials
- **THEN** the system SHALL reset `users.failed_login_count` to 0
- **AND** the system SHALL clear any existing `locked_until`

#### Scenario: Locked user cannot authenticate

- **WHEN** a locked user attempts to login
- **THEN** the system SHALL return HTTP 403 with code `auth.account.locked`
- **AND** the response SHALL include `locked_until` (RFC3339 timestamp)
- **AND** the system SHALL NOT attempt password verification

#### Scenario: Lock expires automatically

- **WHEN** `users.locked_until` is set to a past timestamp
- **THEN** the system SHALL treat the account as unlocked
- **AND** the user SHALL be able to attempt login normally

#### Scenario: Lock check in JWTAuth middleware

- **WHEN** a request arrives with a valid JWT but the user is locked
- **THEN** the system SHALL abort the request with HTTP 403 `auth.account.locked`
- **AND** the system SHALL include `locked_until` in the response params

#### Scenario: Configurable lock threshold and duration

- **WHEN** `authkit.Config.MaxFailedLoginAttempts` is set to a custom value
- **THEN** the system SHALL use that value as the lock threshold
- **AND** `authkit.Config.AccountLockDuration` (default 15 minutes) SHALL control lock duration
