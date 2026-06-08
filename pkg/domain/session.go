package domain

import (
	"time"

	"github.com/google/uuid"
)

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
