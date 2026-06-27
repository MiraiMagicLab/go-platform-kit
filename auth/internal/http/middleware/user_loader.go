package middleware

import (
	"context"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

func loadUserForAuth(ctx context.Context, users ports.UserRepository, cache UserAuthCache, userID uuid.UUID) (domain.User, error) {
	if cache != nil {
		if u, ok, err := cache.Get(ctx, userID); err == nil && ok {
			return u, nil
		}
	}
	u, err := users.GetByID(ctx, userID)
	if err != nil {
		return domain.User{}, err
	}
	if cache != nil {
		_ = cache.Set(ctx, u)
	}
	return u, nil
}
