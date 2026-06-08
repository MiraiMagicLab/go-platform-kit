package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.IdentityRepository = (*IdentityAdapter)(nil)

// IdentityAdapter wraps *postgres.IdentityRepo to implement ports.IdentityRepository.
type IdentityAdapter struct {
	repo *postgres.IdentityRepo
}

func NewIdentityAdapter(repo *postgres.IdentityRepo) *IdentityAdapter {
	return &IdentityAdapter{repo: repo}
}

func (a *IdentityAdapter) FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error) {
	return a.repo.FindUserIDByProvider(ctx, provider, providerSubject)
}

func (a *IdentityAdapter) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error {
	return a.repo.LinkIdentity(ctx, userID, provider, providerSubject, email)
}
