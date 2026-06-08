package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/domain"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/ports"
)

var _ ports.SessionRepository = (*SessionRepoMock)(nil)

// SessionRepoMock is a mock implementation of ports.SessionRepository for testing.
type SessionRepoMock struct {
	CreateFunc           func(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error)
	CreateWithIDFunc     func(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error
	ListActiveFunc       func(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
	TouchFunc            func(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error
	RevokeFunc           func(ctx context.Context, sessionID uuid.UUID) (int64, error)
	RevokeAllExceptFunc  func(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error)
	GetByIDFunc          func(ctx context.Context, sessionID uuid.UUID) (domain.Session, error)
	RevokeAllForUserFunc func(ctx context.Context, userID uuid.UUID) error
	CleanupFunc          func(ctx context.Context, now time.Time) error
}

func (m *SessionRepoMock) Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, userID, deviceName, ip, ua)
	}
	return uuid.New(), nil
}

func (m *SessionRepoMock) CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error {
	if m.CreateWithIDFunc != nil {
		return m.CreateWithIDFunc(ctx, id, userID, deviceName, ip, ua, createdAt)
	}
	return nil
}

func (m *SessionRepoMock) ListActive(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	if m.ListActiveFunc != nil {
		return m.ListActiveFunc(ctx, userID)
	}
	return nil, nil
}

func (m *SessionRepoMock) Touch(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	if m.TouchFunc != nil {
		return m.TouchFunc(ctx, sessionID, ip, ua, deviceName)
	}
	return nil
}

func (m *SessionRepoMock) Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	if m.RevokeFunc != nil {
		return m.RevokeFunc(ctx, sessionID)
	}
	return 1, nil
}

func (m *SessionRepoMock) RevokeAllExcept(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	if m.RevokeAllExceptFunc != nil {
		return m.RevokeAllExceptFunc(ctx, userID, keepSessionID)
	}
	return 0, nil
}

func (m *SessionRepoMock) GetByID(ctx context.Context, sessionID uuid.UUID) (domain.Session, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, sessionID)
	}
	return domain.Session{}, nil
}

func (m *SessionRepoMock) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if m.RevokeAllForUserFunc != nil {
		return m.RevokeAllForUserFunc(ctx, userID)
	}
	return nil
}

func (m *SessionRepoMock) Cleanup(ctx context.Context, now time.Time) error {
	if m.CleanupFunc != nil {
		return m.CleanupFunc(ctx, now)
	}
	return nil
}
