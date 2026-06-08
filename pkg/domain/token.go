package domain

import (
	"time"

	"github.com/google/uuid"
)

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
