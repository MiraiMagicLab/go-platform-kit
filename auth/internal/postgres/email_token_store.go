package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

var _ store.EmailTokenRepository = (*EmailTokenAdapter)(nil)

// EmailTokenAdapter wraps *EmailTokenRepo to implement store.EmailTokenRepository.
type EmailTokenAdapter struct {
	repo *EmailTokenRepo
}

func NewEmailTokenAdapter(repo *EmailTokenRepo) *EmailTokenAdapter {
	return &EmailTokenAdapter{repo: repo}
}

func (a *EmailTokenAdapter) Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error {
	return a.repo.Create(ctx, userID, actionType, tokenHash, expiresAt)
}

func (a *EmailTokenAdapter) Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error) {
	return a.repo.Consume(ctx, actionType, tokenHash, now)
}

func (a *EmailTokenAdapter) Cleanup(ctx context.Context, now time.Time) error {
	return a.repo.Cleanup(ctx, now)
}
