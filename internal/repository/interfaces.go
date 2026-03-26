package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (UserDTO, error)
	GetByID(ctx context.Context, id uuid.UUID) (UserDTO, error)
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error
}

type RBACRepository interface {
	CreateRole(ctx context.Context, name string) (uuid.UUID, error)
	CreatePermission(ctx context.Context, name string) (uuid.UUID, error)
	AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	GetByHash(ctx context.Context, tokenHash string) (RefreshTokenDTO, error)
	Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

type UserDTO struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	TokenVersion int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshTokenDTO struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
