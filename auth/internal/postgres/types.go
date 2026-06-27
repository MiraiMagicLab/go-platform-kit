package postgres

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// UserDTO maps directly to the users table row.
type UserDTO struct {
	ID                   uuid.UUID
	Email                string
	PasswordHash         string
	EmailVerified        bool
	PasswordLoginEnabled bool
	BannedUntil          *time.Time
	BanReason            *string
	TokenVersion         int
	FailedLoginCount     int
	LockedUntil          *time.Time
	DeletedAt            *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// RefreshTokenDTO maps directly to the refresh_tokens table row.
type RefreshTokenDTO struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	SessionID     uuid.UUID
	TokenHash     string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	CreatedAt     time.Time
	IPAddress     *string
	UserAgent     *string
	DeviceName    *string
	LastUsedAt    time.Time
}

// SessionRow represents a login session (device/browser) from the sessions table.
type SessionRow struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	DeviceName *string
	IPAddress  *string
	UserAgent  *string
	CreatedAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
}

// SessionListRow is one logical login session (device/browser), backed by the active refresh token in its chain.
type SessionListRow struct {
	SessionID  uuid.UUID
	RefreshID  uuid.UUID // active refresh token row id (for debugging/support, not secret)
	CreatedAt  time.Time // first token in chain (oldest row for this session_id still present)
	LastUsedAt time.Time
	IPAddress  string
	UserAgent  string
	ExpiresAt  time.Time
	DeviceName string
}

// RotateResult contains the outcome of a refresh token rotation.
type RotateResult struct {
	UserID            uuid.UUID
	SessionID         uuid.UUID
	NewRefreshTokenID *uuid.UUID
	Invalid           bool
	ReplayDetected    bool
}

// MFADTO maps directly to the user_mfa table row.
type MFADTO struct {
	UserID     uuid.UUID
	TOTPSecret string
	Enabled    bool
	EnabledAt  *time.Time
	CreatedAt  time.Time
}

// AuditLogCreate holds the payload for inserting an audit log entry.
type AuditLogCreate struct {
	UserID    *uuid.UUID
	Action    string
	Status    string
	IP        string
	UserAgent string
	Metadata  json.RawMessage
}
