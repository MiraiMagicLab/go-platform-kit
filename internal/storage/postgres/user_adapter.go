package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// Ensure UserAdapter implements ports.UserRepository at compile time.
var _ ports.UserRepository = (*UserAdapter)(nil)

// UserAdapter wraps *postgres.UserRepo to implement ports.UserRepository.
type UserAdapter struct {
	repo *postgres.UserRepo
}

// NewUserAdapter creates a UserAdapter wrapping the given UserRepo.
func NewUserAdapter(repo *postgres.UserRepo) *UserAdapter {
	return &UserAdapter{repo: repo}
}

func (a *UserAdapter) Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	return a.repo.Create(ctx, email, passwordHash)
}

func (a *UserAdapter) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	return a.repo.CreateOAuthUser(ctx, email, passwordHash)
}

func (a *UserAdapter) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	dto, err := a.repo.GetByEmail(ctx, email)
	if err != nil {
		return domain.User{}, err
	}
	return dtoToUser(dto), nil
}

func (a *UserAdapter) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	dto, err := a.repo.GetByID(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	return dtoToUser(dto), nil
}

func (a *UserAdapter) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	return a.repo.IncrementTokenVersion(ctx, userID)
}

func (a *UserAdapter) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	return a.repo.SetPassword(ctx, userID, passwordHash)
}

func (a *UserAdapter) SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	return a.repo.SetEmailVerified(ctx, userID, verified)
}

func (a *UserAdapter) SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error {
	return a.repo.SetBan(ctx, userID, bannedUntil, reason)
}

func (a *UserAdapter) IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error {
	return a.repo.IncrementFailedLogin(ctx, userID)
}

func (a *UserAdapter) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	return a.repo.ResetFailedLogin(ctx, userID)
}

func (a *UserAdapter) SetLock(ctx context.Context, userID uuid.UUID, until time.Time) error {
	return a.repo.SetLock(ctx, userID, until)
}

func (a *UserAdapter) SoftDelete(ctx context.Context, userID uuid.UUID) error {
	return a.repo.SoftDelete(ctx, userID)
}

func (a *UserAdapter) ListUsers(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error) {
	dtoFilter := postgres.ListUsersFilter{
		Search:               filter.Search,
		Email:                filter.Email,
		EmailVerified:        filter.EmailVerified,
		PasswordLoginEnabled: filter.PasswordLoginEnabled,
		IsBanned:             filter.IsBanned,
		CreatedFrom:          filter.CreatedFrom,
		CreatedTo:            filter.CreatedTo,
		SortBy:               filter.SortBy,
		SortOrder:            filter.SortOrder,
	}
	dtos, total, err := a.repo.ListUsers(ctx, page, pageSize, dtoFilter)
	if err != nil {
		return nil, 0, err
	}
	users := make([]domain.User, len(dtos))
	for i, dto := range dtos {
		users[i] = dtoToUser(dto)
	}
	return users, total, nil
}

func dtoToUser(dto postgres.UserDTO) domain.User {
	return domain.User{
		ID:                   dto.ID,
		Email:                dto.Email,
		PasswordHash:         dto.PasswordHash,
		EmailVerified:        dto.EmailVerified,
		PasswordLoginEnabled: dto.PasswordLoginEnabled,
		BannedUntil:          dto.BannedUntil,
		BanReason:            dto.BanReason,
		TokenVersion:         dto.TokenVersion,
		FailedLoginCount:     dto.FailedLoginCount,
		LockedUntil:          dto.LockedUntil,
		DeletedAt:            dto.DeletedAt,
		CreatedAt:            dto.CreatedAt,
		UpdatedAt:            dto.UpdatedAt,
	}
}
