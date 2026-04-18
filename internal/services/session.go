package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
)

// ErrSessionNotFound is returned when no active refresh row exists for the given session id.
var ErrSessionNotFound = errors.New("session not found or already revoked")

// SessionService exposes user-facing session (device) management backed by refresh token rows.
type SessionService struct {
	refresh  *postgres.RefreshTokenRepo
	denylist AccessTokenDenylist
}

func NewSessionService(refresh *postgres.RefreshTokenRepo, denylist AccessTokenDenylist) *SessionService {
	if denylist == nil {
		denylist = NoopAccessTokenDenylist{}
	}
	return &SessionService{refresh: refresh, denylist: denylist}
}

func (s *SessionService) List(ctx context.Context, userID uuid.UUID) ([]postgres.SessionListRow, error) {
	return s.refresh.ListActiveSessions(ctx, userID)
}

// RevokeSession revokes all refresh tokens for targetSessionID. If it matches the current access token session,
// the access JTI is denylisted so this device loses API access immediately (until access JWT expires anyway).
func (s *SessionService) RevokeSession(ctx context.Context, userID, targetSessionID, currentAccessSession uuid.UUID, accessJTI string, accessExp time.Time) error {
	n, err := s.refresh.RevokeAllForSession(ctx, userID, targetSessionID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	if targetSessionID == currentAccessSession && accessJTI != "" {
		ttl := time.Until(accessExp)
		if ttl > 0 {
			_ = s.denylist.Deny(ctx, accessJTI, ttl)
		}
	}
	return nil
}

// RevokeOtherSessions revokes every active session except keepSessionID (typically the current browser).
func (s *SessionService) RevokeOtherSessions(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	if keepSessionID == uuid.Nil {
		return errors.New("keep session id required")
	}
	_, err := s.refresh.RevokeAllExceptSession(ctx, userID, keepSessionID)
	return err
}
