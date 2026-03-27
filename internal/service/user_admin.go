package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repository"
)

type UserAdminService struct {
	users   repository.UserRepository
	refresh repository.RefreshTokenRepository
}

func NewUserAdminService(users repository.UserRepository, refresh repository.RefreshTokenRepository) *UserAdminService {
	return &UserAdminService{users: users, refresh: refresh}
}

func (s *UserAdminService) BanUser(ctx context.Context, userID uuid.UUID, until time.Time, reason string) error {
	if err := s.users.SetBan(ctx, userID, &until, reason); err != nil {
		return err
	}
	_ = s.users.IncrementTokenVersion(ctx, userID)
	_ = s.refresh.RevokeAllForUser(ctx, userID)
	return nil
}

func (s *UserAdminService) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	return s.users.SetBan(ctx, userID, nil, "")
}
