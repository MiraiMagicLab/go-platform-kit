package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// ErrSessionNotFound is returned when no active session exists for the given session id.
var ErrSessionNotFound = errors.New("session not found or already revoked")

// SessionService exposes user-facing session (device) management.
type SessionService struct {
	sessions ports.SessionRepository
	refresh  ports.RefreshTokenRepository
	denylist ports.AccessTokenDenylist
}

// NewSessionService creates a SessionService. If denylist is nil, a no-op denylist is used.
func NewSessionService(sessions ports.SessionRepository, refresh ports.RefreshTokenRepository, denylist ports.AccessTokenDenylist) *SessionService {
	if denylist == nil {
		denylist = ports.NoopAccessTokenDenylist{}
	}
	return &SessionService{sessions: sessions, refresh: refresh, denylist: denylist}
}

// List returns all active (non-revoked, non-expired) sessions for the given user.
func (s *SessionService) List(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	return s.sessions.ListActive(ctx, userID)
}

// CreateSession creates a new session record for the given user and returns its ID.
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	return s.sessions.Create(ctx, userID, deviceName, ip, ua)
}

// TouchSession updates the session's last-seen metadata (IP, user agent, device name).
func (s *SessionService) TouchSession(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	return s.sessions.Touch(ctx, sessionID, ip, ua, deviceName)
}

// RevokeSession revokes a single session. If the revoked session is the caller's
// current session, the current access token JTI is added to the denylist.
// It returns ErrSessionNotFound if the session does not exist or is already revoked.
func (s *SessionService) RevokeSession(ctx context.Context, userID, targetSessionID, currentAccessSession uuid.UUID, accessJTI string, accessExp time.Time) error {
	n, err := s.sessions.Revoke(ctx, targetSessionID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	_, _ = s.refresh.RevokeAllForSession(ctx, userID, targetSessionID)
	if targetSessionID == currentAccessSession && accessJTI != "" {
		ttl := time.Until(accessExp)
		if ttl > 0 {
			_ = s.denylist.Deny(ctx, accessJTI, ttl)
		}
	}
	return nil
}

// RevokeOtherSessions revokes all sessions for the user except the one identified
// by keepSessionID, along with their associated refresh tokens.
func (s *SessionService) RevokeOtherSessions(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	if keepSessionID == uuid.Nil {
		return errors.New("keep session id required")
	}
	_, err := s.sessions.RevokeAllExcept(ctx, userID, keepSessionID)
	if err != nil {
		return err
	}
	_, _ = s.refresh.RevokeAllExceptSession(ctx, userID, keepSessionID)
	return nil
}

// RevokeAllSessions revokes every session and refresh token for the given user.
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.refresh.RevokeAllForUser(ctx, userID)
}
