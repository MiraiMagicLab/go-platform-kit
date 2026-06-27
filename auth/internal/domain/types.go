package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User is the aggregate root for authentication and authorization.
type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                string     `json:"email"`
	PasswordHash         string     `json:"-"`
	EmailVerified        bool       `json:"email_verified"`
	PasswordLoginEnabled bool       `json:"password_login_enabled"`
	BannedUntil          *time.Time `json:"banned_until,omitempty"`
	BanReason            *string    `json:"ban_reason,omitempty"`
	TokenVersion         int        `json:"-"`
	FailedLoginCount     int        `json:"-"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// IsBanned returns true if the user is currently banned.
func (u *User) IsBanned() bool {
	return u.BannedUntil != nil && time.Now().Before(*u.BannedUntil)
}

// IsLocked returns true if the account is temporarily locked due to failed login attempts.
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
}

// IsDeleted returns true if the user has been soft-deleted.
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// CanLogin checks all preconditions for login.
func (u *User) CanLogin(requireEmailVerified bool) error {
	if !u.PasswordLoginEnabled {
		return ErrInvalidCredentials
	}
	if u.IsBanned() {
		return ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if u.IsLocked() {
		return ErrAccountLocked{Until: u.LockedUntil}
	}
	if u.IsDeleted() {
		return ErrInvalidCredentials
	}
	if requireEmailVerified && !u.EmailVerified {
		return ErrEmailNotVerified{}
	}
	return nil
}

// IsPasswordLoginEnabled returns true if the user can log in with email/password.
func (u *User) IsPasswordLoginEnabled() bool {
	return u.PasswordLoginEnabled
}

// Session represents a login session (device/browser).
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	DeviceName *string    `json:"device_name,omitempty"`
	IPAddress  *string    `json:"ip_address,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// IsRevoked returns true if the session has been revoked.
func (s *Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// SessionListInfo represents a logical login session derived from active refresh tokens.
type SessionListInfo struct {
	SessionID  uuid.UUID
	RefreshID  uuid.UUID
	CreatedAt  time.Time
	LastUsedAt time.Time
	IPAddress  string
	UserAgent  string
	ExpiresAt  time.Time
	DeviceName string
}

// ClientMeta carries client connection info stored on refresh-token / session rows.
type ClientMeta struct {
	IP string
	UA string
}

// RefreshToken represents a refresh token in the rotation chain.
type RefreshToken struct {
	ID            uuid.UUID  `json:"id"`
	UserID        uuid.UUID  `json:"user_id"`
	SessionID     uuid.UUID  `json:"session_id"`
	TokenHash     string     `json:"-"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason *string    `json:"revoked_reason,omitempty"`
	ReplacedBy    *uuid.UUID `json:"replaced_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	IPAddress     *string    `json:"-"`
	UserAgent     *string    `json:"-"`
	DeviceName    *string    `json:"device_name,omitempty"`
	LastUsedAt    time.Time  `json:"last_used_at"`
}

// IsExpired returns true if the token has expired.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRevoked returns true if the token has been revoked.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsActive returns true if the token is neither expired nor revoked.
func (t *RefreshToken) IsActive() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// RotateResult contains the outcome of a refresh token rotation.
type RotateResult struct {
	UserID            uuid.UUID
	SessionID         uuid.UUID
	NewRefreshTokenID *uuid.UUID
	Invalid           bool
	ReplayDetected    bool
}

// AccessTokenMeta carries access token metadata from the JWT claims.
type AccessTokenMeta struct {
	JTI       string
	ExpiresAt time.Time
}

// Role represents a named role in the RBAC system.
type Role struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Permission represents a named permission in the RBAC system.
type Permission struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// MFAConfig represents a user's TOTP MFA configuration.
type MFAConfig struct {
	UserID     uuid.UUID  `json:"user_id"`
	TOTPSecret string     `json:"-"`
	Enabled    bool       `json:"enabled"`
	EnabledAt  *time.Time `json:"enabled_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// MFASetup contains the data returned when setting up TOTP MFA.
type MFASetup struct {
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// OAuthIdentity represents a linked OAuth provider identity.
type OAuthIdentity struct {
	UserID          uuid.UUID `json:"user_id"`
	Provider        string    `json:"provider"`
	ProviderSubject string    `json:"provider_subject"`
	Email           *string   `json:"email,omitempty"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	UserID    *uuid.UUID      `json:"user_id,omitempty"`
	Action    string          `json:"action"`
	Status    string          `json:"status"`
	IP        string          `json:"ip,omitempty"`
	UserAgent string          `json:"user_agent,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// EmailActionToken represents a one-time token for email verification or password reset.
type EmailActionToken struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ActionType string     `json:"action_type"`
	TokenHash  string     `json:"-"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}
