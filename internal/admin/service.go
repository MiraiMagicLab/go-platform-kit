package admin

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// UserAdminService handles admin operations on users: ban, unban, delete, list.
type UserAdminService struct {
	users   ports.UserRepository
	refresh ports.RefreshTokenRepository
}

func NewUserAdminService(users ports.UserRepository, refresh ports.RefreshTokenRepository) *UserAdminService {
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

func (s *UserAdminService) ListUsers(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error) {
	return s.users.ListUsers(ctx, page, pageSize, filter)
}

func (s *UserAdminService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	_ = s.users.IncrementTokenVersion(ctx, userID)
	_ = s.refresh.RevokeAllForUser(ctx, userID)
	return s.users.SoftDelete(ctx, userID)
}
