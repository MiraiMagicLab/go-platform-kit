## ADDED Requirements

### Requirement: MFA Disable Requires Password or Active MFA Code

The system SHALL require verification of the user's identity before allowing MFA to be disabled. The request MUST include either the user's current password or a valid active MFA code.

#### Scenario: Disable with valid password succeeds

- **WHEN** an authenticated user calls `POST /mfa/disable` with `{"password": "correctPassword"}`
- **THEN** the system SHALL verify the password against `users.password_hash`
- **AND** if the password is correct, the system SHALL disable MFA for the user
- **AND** the system SHALL revoke all recovery codes for the user
- **AND** the system SHALL return HTTP 200 with `{"ok": true}`

#### Scenario: Disable with valid MFA code succeeds

- **WHEN** an authenticated user calls `POST /mfa/disable` with `{"code": "123456"}` (valid TOTP)
- **THEN** the system SHALL validate the code against the user's active TOTP secret
- **AND** if the code is valid, the system SHALL disable MFA for the user
- **AND** the system SHALL return HTTP 200 with `{"ok": true}`

#### Scenario: Disable with valid recovery code succeeds

- **WHEN** an authenticated user calls `POST /mfa/disable` with `{"code": "ABCD1234EF"}` (unused recovery code)
- **THEN** the system SHALL validate the code against stored recovery code hashes
- **AND** if the code is valid and unused, the system SHALL mark it as used and disable MFA
- **AND** the system SHALL return HTTP 200 with `{"ok": true}`

#### Scenario: Disable without verification fails

- **WHEN** an authenticated user calls `POST /mfa/disable` with neither `password` nor `code`
- **THEN** the system SHALL return HTTP 400 `common.invalid.request`

#### Scenario: Disable with wrong password fails

- **WHEN** an authenticated user calls `POST /mfa/disable` with `{"password": "wrongPassword"}`
- **THEN** the system SHALL return HTTP 403 `auth.forbidden`
- **AND** the MFA settings SHALL remain unchanged
- **AND** the system SHALL NOT reveal whether MFA is enabled

#### Scenario: Disable with wrong MFA code fails

- **WHEN** an authenticated user calls `POST /mfa/disable` with `{"code": "000000"}`
- **THEN** the system SHALL return HTTP 403 `auth.forbidden`
- **AND** the MFA settings SHALL remain unchanged

#### Scenario: MFA disable verification is configurable

- **WHEN** `authkit.Config.RequirePasswordForMFADisable` is `false`
- **THEN** the system SHALL allow MFA disable with only a valid access token (legacy behavior)
- **DEFAULT** value SHALL be `true`

#### Scenario: MFA disable audit logging

- **WHEN** MFA is successfully disabled
- **THEN** the system SHALL log `mfa.disable` action with `status: success` to `audit_logs`
- **WHEN** MFA disable fails due to invalid verification
- **THEN** the system SHALL log `mfa.disable` action with `status: failed`
