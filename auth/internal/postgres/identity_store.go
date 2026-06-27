package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

var _ store.IdentityRepository = (*IdentityAdapter)(nil)

// IdentityAdapter wraps *IdentityRepo to implement store.IdentityRepository.
type IdentityAdapter struct {
	repo *IdentityRepo
}

func NewIdentityAdapter(repo *IdentityRepo) *IdentityAdapter {
	return &IdentityAdapter{repo: repo}
}

func (a *IdentityAdapter) FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error) {
	return a.repo.FindUserIDByProvider(ctx, provider, providerSubject)
}

func (a *IdentityAdapter) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error {
	return a.repo.LinkIdentity(ctx, userID, provider, providerSubject, email)
}
