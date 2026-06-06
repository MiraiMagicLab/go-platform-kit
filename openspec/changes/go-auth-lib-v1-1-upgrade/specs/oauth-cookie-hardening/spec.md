## ADDED Requirements

### Requirement: OAuth State Cookie Security Hardening

The OAuth CSRF state cookie SHALL set security attributes to prevent cross-site attacks and state leakage.

#### Scenario: OAuth login sets secure state cookie

- **WHEN** `GET /oauth/:provider/login` is called
- **THEN** the system SHALL set a cookie named `oauth_state` with `SameSite=Lax`
- **AND** the cookie SHALL have `Path=/auth` (or the mounted auth prefix)
- **AND** the cookie SHALL have `HttpOnly=true`
- **AND** the cookie SHALL have `MaxAge=300` (5 minutes)
- **AND** the cookie value SHALL be a cryptographically random 32-character hex string

#### Scenario: OAuth callback validates state cookie

- **WHEN** `GET /oauth/:provider/callback` receives a request without a matching `oauth_state` cookie
- **THEN** the system SHALL return HTTP 400 `oauth.invalid.state`
- **AND** no OAuth exchange SHALL be initiated

#### Scenario: State cookie is cleared after use

- **WHEN** `GET /oauth/:provider/callback` successfully validates the state
- **THEN** the system SHALL clear the `oauth_state` cookie by setting `MaxAge=-1`
- **AND** the cookie SHALL NOT be usable for a second callback attempt

#### Scenario: State cookie Secure flag is configurable

- **WHEN** `authkit.Config.OAuthCookieSecure` is `true`
- **THEN** the `Secure` attribute SHALL be set on the `oauth_state` cookie
- **DEFAULT** value SHALL be `false` (to support HTTP in development)
- **PRODUCTION** hosts SHALL set `OAuthCookieSecure=true`
