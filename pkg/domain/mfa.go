package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

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
