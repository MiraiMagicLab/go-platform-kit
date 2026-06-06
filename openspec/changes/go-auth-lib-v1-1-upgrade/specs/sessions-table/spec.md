## ADDED Requirements

### Requirement: Sessions Table as Authoritative Session Entity

The system SHALL maintain a `sessions` table as the authoritative entity representing a user login session (device/browser). Each session corresponds to one logical login device. Multiple refresh token rotations belong to a single session.

#### Scenario: New login creates a session

- **WHEN** a user completes authentication (password login, OAuth callback, or MFA completion)
- **THEN** the system SHALL create exactly one new row in the `sessions` table with `user_id`, `device_name`, `ip_address`, `user_agent`, `created_at = NOW()`, `last_seen_at = NOW()`, and `revoked_at = NULL`
- **AND** the refresh token chain created for this login SHALL reference this session via `session_id`

#### Scenario: Refresh token rotation updates last_seen_at

- **WHEN** a refresh token is rotated for an active session
- **THEN** the system SHALL update `sessions.last_seen_at` to `NOW()` for that session
- **AND** `sessions.ip_address` and `sessions.user_agent` SHALL be updated to the most recent values from the refresh request

#### Scenario: Revoke one device invalidates session

- **WHEN** a user or admin requests to revoke a specific session by `session_id`
- **THEN** the system SHALL set `sessions.revoked_at = NOW()`
- **AND** the system SHALL revoke all refresh tokens belonging to that session
- **AND** if the revoked session matches the current access token's session ID, the system SHALL add the access token JTI to the denylist

#### Scenario: Revoke other devices preserves current session

- **WHEN** a user calls `POST /sessions/revoke-others`
- **THEN** the system SHALL set `sessions.revoked_at = NOW()` for all sessions belonging to the user EXCEPT the session identified by the current access token's `sid`
- **AND** the system SHALL revoke all refresh tokens for all revoked sessions

#### Scenario: Session listing returns active sessions

- **WHEN** an authenticated user calls `GET /sessions`
- **THEN** the system SHALL return all sessions for that user where `revoked_at IS NULL` and `last_seen_at > NOW() - session_ttl` (30 days default)
- **AND** each session SHALL include `device_name`, `ip_address`, `user_agent`, `created_at`, `last_seen_at`, and a `current: true|false` flag indicating whether the session matches the access token's `sid`

#### Scenario: Expired session is not listed

- **WHEN** a session has `last_seen_at` older than the session TTL (configurable, default 30 days)
- **THEN** the system SHALL NOT include that session in the `GET /sessions` response

### Requirement: Device Name Parsing from User-Agent

The system SHALL parse the `user_agent` string to extract a human-readable `device_name` (e.g., "Chrome on Windows", "Safari on iPhone") and store it in both `sessions.device_name` and `refresh_tokens.device_name`.

#### Scenario: Device name is cached on session creation

- **WHEN** a new session is created during login
- **THEN** the system SHALL parse the `User-Agent` request header and store the result in `sessions.device_name`
- **AND** the same parsed value SHALL be stored in `refresh_tokens.device_name` for the initial refresh token row

#### Scenario: Device name is updated on refresh

- **WHEN** a refresh token is rotated
- **THEN** `sessions.device_name` SHALL be updated to the latest parsed `User-Agent` if it has changed
