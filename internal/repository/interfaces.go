package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (UserDTO, error)
	GetByID(ctx context.Context, id uuid.UUID) (UserDTO, error)
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error
	SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error
	SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error
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
	Cleanup(ctx context.Context, now time.Time) error
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
	Cleanup(ctx context.Context, now time.Time) error
}

type AuditRepository interface {
	Create(ctx context.Context, in AuditLogCreate) error
}

type EmailTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error
	Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error)
	Cleanup(ctx context.Context, now time.Time) error
}

type UserDTO struct {
	ID                   uuid.UUID
	Email                string
	PasswordHash         string
	EmailVerified        bool
	PasswordLoginEnabled bool
	BannedUntil          *time.Time
	BanReason            *string
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

type AuditLogCreate struct {
	UserID    *uuid.UUID
	Action    string
	Status    string
	IP        string
	UserAgent string
	Metadata  json.RawMessage
}

type MFADTO struct {
	UserID     uuid.UUID
	TOTPSecret string
	Enabled    bool
	EnabledAt  *time.Time
	CreatedAt  time.Time
}
