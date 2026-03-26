package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (UserDTO, error)
	GetByID(ctx context.Context, id uuid.UUID) (UserDTO, error)
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error
}

type IdentityRepository interface {
	FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error)
	LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error
}

type MFARepository interface {
	UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error
	GetMFA(ctx context.Context, userID uuid.UUID) (MFADTO, bool, error)
	EnableMFA(ctx context.Context, userID uuid.UUID) error
	DisableMFA(ctx context.Context, userID uuid.UUID) error
	ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error)
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
	Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newExpiresAt time.Time) (RotateResult, error)
}

type UserDTO struct {
	ID                   uuid.UUID
	Email                string
	PasswordHash         string
	PasswordLoginEnabled bool
	TokenVersion         int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type RefreshTokenDTO struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TokenHash     string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	CreatedAt     time.Time
}

type RotateResult struct {
	UserID            uuid.UUID
	NewRefreshTokenID *uuid.UUID
	Invalid           bool
	ReplayDetected    bool
}

type MFADTO struct {
	UserID     uuid.UUID
	TOTPSecret string
	Enabled    bool
	EnabledAt  *time.Time
	CreatedAt  time.Time
}
