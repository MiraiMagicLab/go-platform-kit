package session

import (
	"context"
	"errors"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
	"time"

	"github.com/google/uuid"
)

// ErrSessionNotFound is returned when no active session exists for the given session id.
var ErrSessionNotFound = errors.New("session not found or already revoked")

// SessionService exposes user-facing session (device) management.
type SessionService struct {
	sessions store.SessionRepository
	refresh  store.RefreshTokenRepository
	denylist store.AccessTokenDenylist
}

func NewSessionService(sessions store.SessionRepository, refresh store.RefreshTokenRepository, denylist store.AccessTokenDenylist) *SessionService {
	if denylist == nil {
		denylist = store.NoopAccessTokenDenylist{}
	}
	return &SessionService{sessions: sessions, refresh: refresh, denylist: denylist}
}

func (s *SessionService) List(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	return s.sessions.ListActive(ctx, userID)
}

func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	return s.sessions.Create(ctx, userID, deviceName, ip, ua)
}

func (s *SessionService) TouchSession(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	return s.sessions.Touch(ctx, sessionID, ip, ua, deviceName)
}

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

func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	return s.refresh.RevokeAllForUser(ctx, userID)
}
