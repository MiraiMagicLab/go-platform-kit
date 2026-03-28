package postgres

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type UserDTO struct {
	ID                   uuid.UUID
	Email                string
	PasswordHash         string
	EmailVerified        bool
	PasswordLoginEnabled bool
	BannedUntil          *time.Time
	BanReason            *string
	TokenVersion         int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type RefreshTokenDTO struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TokenHash     string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	CreatedAt     time.Time
}

type RotateResult struct {
	UserID            uuid.UUID
	NewRefreshTokenID *uuid.UUID
	Invalid           bool
	ReplayDetected    bool
}

type MFADTO struct {
	UserID     uuid.UUID
	TOTPSecret string
	Enabled    bool
	EnabledAt  *time.Time
	CreatedAt  time.Time
}

type AuditLogCreate struct {
	UserID    *uuid.UUID
	Action    string
	Status    string
	IP        string
	UserAgent string
	Metadata  json.RawMessage
}

