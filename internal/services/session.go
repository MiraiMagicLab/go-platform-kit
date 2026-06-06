package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
)

// ErrSessionNotFound is returned when no active session exists for the given session id.
var ErrSessionNotFound = errors.New("session not found or already revoked")

// SessionService exposes user-facing session (device) management backed by the sessions table.
type SessionService struct {
	sessions *postgres.SessionsRepo
	refresh  *postgres.RefreshTokenRepo
	denylist AccessTokenDenylist
}

func NewSessionService(sessions *postgres.SessionsRepo, refresh *postgres.RefreshTokenRepo, denylist AccessTokenDenylist) *SessionService {
	if denylist == nil {
		denylist = NoopAccessTokenDenylist{}
	}
	return &SessionService{sessions: sessions, refresh: refresh, denylist: denylist}
}

func (s *SessionService) List(ctx context.Context, userID uuid.UUID) ([]postgres.SessionRow, error) {
	return s.sessions.ListActive(ctx, userID)
}

// CreateSession creates a new session record and returns the session ID.
// Call this before creating refresh tokens for a new login.
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	return s.sessions.Create(ctx, userID, deviceName, ip, ua)
}

// TouchSession updates last_seen_at and optionally IP/UA/device_name.
// Call this on every refresh token rotation.
func (s *SessionService) TouchSession(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	return s.sessions.Touch(ctx, sessionID, ip, ua, deviceName)
}

// RevokeSession revokes the target session and all its refresh tokens.
// If it matches the current access token session, the access JTI is denylisted.
func (s *SessionService) RevokeSession(ctx context.Context, userID, targetSessionID, currentAccessSession uuid.UUID, accessJTI string, accessExp time.Time) error {
	n, err := s.sessions.Revoke(ctx, targetSessionID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	// Also revoke refresh tokens for this session.
	_, _ = s.refresh.RevokeAllForSession(ctx, userID, targetSessionID)
	if targetSessionID == currentAccessSession && accessJTI != "" {
		ttl := time.Until(accessExp)
		if ttl > 0 {
			_ = s.denylist.Deny(ctx, accessJTI, ttl)
		}
	}
	return nil
}

// RevokeOtherSessions revokes every active session except keepSessionID.
func (s *SessionService) RevokeOtherSessions(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	if keepSessionID == uuid.Nil {
		return errors.New("keep session id required")
	}
	// Revoke sessions.
	n, err := s.sessions.RevokeAllExcept(ctx, userID, keepSessionID)
	if err != nil {
		return err
	}
	_ = n
	// Revoke all refresh tokens except the keep session.
	_, _ = s.refresh.RevokeAllExceptSession(ctx, userID, keepSessionID)
	return nil
}

// RevokeAllSessions revokes all sessions and refresh tokens for a user (full logout).
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.refresh.RevokeAllForUser(ctx, userID)
}
