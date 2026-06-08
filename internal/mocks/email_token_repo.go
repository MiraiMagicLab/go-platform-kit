package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.EmailTokenRepository = (*EmailTokenRepoMock)(nil)

// EmailTokenRepoMock is a mock implementation of ports.EmailTokenRepository for testing.
type EmailTokenRepoMock struct {
	CreateFunc  func(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error
	ConsumeFunc func(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error)
	CleanupFunc func(ctx context.Context, now time.Time) error
}

func (m *EmailTokenRepoMock) Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, userID, actionType, tokenHash, expiresAt)
	}
	return nil
}

func (m *EmailTokenRepoMock) Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error) {
	if m.ConsumeFunc != nil {
		return m.ConsumeFunc(ctx, actionType, tokenHash, now)
	}
	return uuid.Nil, false, nil
}

func (m *EmailTokenRepoMock) Cleanup(ctx context.Context, now time.Time) error {
	if m.CleanupFunc != nil {
		return m.CleanupFunc(ctx, now)
	}
	return nil
}
