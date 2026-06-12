package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// Ensure RefreshTokenRepoMock implements ports.RefreshTokenRepository at compile time.
var _ ports.RefreshTokenRepository = (*RefreshTokenRepoMock)(nil)

// RefreshTokenRepoMock is a mock implementation of ports.RefreshTokenRepository for testing.
type RefreshTokenRepoMock struct {
	mu sync.RWMutex

	CreateFunc                 func(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error)
	GetByHashFunc              func(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	RevokeFunc                 func(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error
	RevokeAllForUserFunc       func(ctx context.Context, userID uuid.UUID) error
	RevokeAllForSessionFunc    func(ctx context.Context, userID, sessionID uuid.UUID) (int64, error)
	RevokeAllExceptSessionFunc func(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error)
	RotateFunc                 func(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, deviceName string) (domain.RotateResult, error)
	CleanupFunc                func(ctx context.Context, now time.Time) error
	ListActiveSessionsFunc     func(ctx context.Context, userID uuid.UUID) ([]domain.SessionListInfo, error)

	// Call tracking
	RevokeAllForUserCalls []uuid.UUID
	RotateCalls           []RotateCall
}

type RotateCall struct {
	OldHash string
	NewHash string
	Expires time.Time
	IP      string
	UA      string
	Device  string
}

func (m *RefreshTokenRepoMock) Create(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, userID, sessionID, tokenHash, expiresAt, ip, ua, deviceName)
	}
	return uuid.New(), nil
}

func (m *RefreshTokenRepoMock) GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	if m.GetByHashFunc != nil {
		return m.GetByHashFunc(ctx, tokenHash)
	}
	return domain.RefreshToken{}, nil
}

func (m *RefreshTokenRepoMock) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	if m.RevokeFunc != nil {
		return m.RevokeFunc(ctx, refreshTokenID, replacedBy)
	}
	return nil
}

func (m *RefreshTokenRepoMock) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	m.RevokeAllForUserCalls = append(m.RevokeAllForUserCalls, userID)
	m.mu.Unlock()
	if m.RevokeAllForUserFunc != nil {
		return m.RevokeAllForUserFunc(ctx, userID)
	}
	return nil
}

func (m *RefreshTokenRepoMock) RevokeAllForSession(ctx context.Context, userID, sessionID uuid.UUID) (int64, error) {
	if m.RevokeAllForSessionFunc != nil {
		return m.RevokeAllForSessionFunc(ctx, userID, sessionID)
	}
	return 0, nil
}

func (m *RefreshTokenRepoMock) RevokeAllExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	if m.RevokeAllExceptSessionFunc != nil {
		return m.RevokeAllExceptSessionFunc(ctx, userID, keepSessionID)
	}
	return 0, nil
}

func (m *RefreshTokenRepoMock) Rotate(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, deviceName string) (domain.RotateResult, error) {
	m.mu.Lock()
	m.RotateCalls = append(m.RotateCalls, RotateCall{
		OldHash: oldHash, NewHash: newHash, Expires: newExpires,
		IP: ip, UA: ua, Device: deviceName,
	})
	m.mu.Unlock()
	if m.RotateFunc != nil {
		return m.RotateFunc(ctx, oldHash, newHash, newExpires, ip, ua, deviceName)
	}
	return domain.RotateResult{}, nil
}

func (m *RefreshTokenRepoMock) Cleanup(ctx context.Context, now time.Time) error {
	if m.CleanupFunc != nil {
		return m.CleanupFunc(ctx, now)
	}
	return nil
}

func (m *RefreshTokenRepoMock) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionListInfo, error) {
	if m.ListActiveSessionsFunc != nil {
		return m.ListActiveSessionsFunc(ctx, userID)
	}
	return nil, nil
}
