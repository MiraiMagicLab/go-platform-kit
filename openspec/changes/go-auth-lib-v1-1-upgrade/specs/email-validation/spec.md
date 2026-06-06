## ADDED Requirements

### Requirement: Email Format Validation on Registration

The system SHALL validate email format using `net/mail.ParseAddress` plus length and structural sanity checks before accepting a registration request.

#### Scenario: Valid email passes validation

- **WHEN** a user submits `POST /register` with email `user@example.com`
- **THEN** `mail.ParseAddress("user@example.com")` SHALL return successfully
- **AND** the registration SHALL proceed

#### Scenario: Email without @ symbol is rejected

- **WHEN** a user submits `POST /register` with email `userexample.com`
- **THEN** the system SHALL return HTTP 400 `auth.invalid.email`

#### Scenario: Email with local part over 64 characters is rejected

- **WHEN** a user submits `POST /register` with email `a...a@example.com` where local part exceeds 64 characters
- **THEN** the system SHALL return HTTP 400 `auth.invalid.email`

#### Scenario: Email with domain over 255 characters is rejected

- **WHEN** a user submits `POST /register` with email `user@a...a.com` where domain exceeds 255 characters
- **THEN** the system SHALL return HTTP 400 `auth.invalid.email`

#### Scenario: Quoted-string email addresses are parsed correctly

- **WHEN** a user submits `POST /register` with email `"John Doe" <john@example.com>`
- **THEN** the system SHALL extract `john@example.com` as the canonical address
- **AND** the display name portion SHALL be discarded

#### Scenario: Empty email is rejected

- **WHEN** a user submits `POST /register` with email `""`
- **THEN** the system SHALL return HTTP 400 `auth.invalid.email`

#### Scenario: Custom email validator is used when provided

- **WHEN** `authkit.Config.EmailValidator` is set to a custom function
- **THEN** the custom function SHALL be called instead of the built-in validator
- **AND** the system SHALL use the custom function's result to accept or reject the email
