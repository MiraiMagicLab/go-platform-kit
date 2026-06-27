package ports

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
)

// ListUsersFilter defines filtering options for listing users.
type ListUsersFilter struct {
	Search               string
	Email                string
	EmailVerified        *bool
	PasswordLoginEnabled *bool
	IsBanned             *bool
	CreatedFrom          *time.Time
	CreatedTo            *time.Time
	SortBy               string
	SortOrder            string
}

// UserRepository defines persistence operations for users.
type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error
	SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error
	SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error
	IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error
	ResetFailedLogin(ctx context.Context, userID uuid.UUID) error
	SetLock(ctx context.Context, userID uuid.UUID, until time.Time) error
	SoftDelete(ctx context.Context, userID uuid.UUID) error
	ListUsers(ctx context.Context, page, pageSize int, filter ListUsersFilter) ([]domain.User, int, error)
}

// RefreshTokenRepository defines persistence for refresh tokens.
type RefreshTokenRepository interface {
	Create(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error)
	GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	RevokeAllForSession(ctx context.Context, userID, sessionID uuid.UUID) (int64, error)
	RevokeAllExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error)
	Rotate(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, deviceName string) (domain.RotateResult, error)
	Cleanup(ctx context.Context, now time.Time) error
	ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionListInfo, error)
}

// SessionRepository defines persistence for sessions.
type SessionRepository interface {
	Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error)
	CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error
	ListActive(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
	Touch(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error
	Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error)
	RevokeAllExcept(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error)
	GetByID(ctx context.Context, sessionID uuid.UUID) (domain.Session, error)
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	Cleanup(ctx context.Context, now time.Time) error
}

// RBACRepository defines persistence for roles and permissions.
type RBACRepository interface {
	CreateRole(ctx context.Context, name string) (uuid.UUID, error)
	CreatePermission(ctx context.Context, name string) (uuid.UUID, error)
	AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	ListUserIDsByRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)
	ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// MFARepository defines persistence for MFA configuration and recovery codes.
type MFARepository interface {
	UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error
	GetMFA(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error)
	EnableMFA(ctx context.Context, userID uuid.UUID) error
	DisableMFA(ctx context.Context, userID uuid.UUID) error
	ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error)
	Cleanup(ctx context.Context, now time.Time) error
}

// IdentityRepository defines persistence for OAuth identities.
type IdentityRepository interface {
	FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error)
	LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error
}

// AuditRepository defines persistence for audit logs.
type AuditRepository interface {
	Create(ctx context.Context, entry domain.AuditEntry) error
}

// EmailTokenRepository defines persistence for email action tokens.
type EmailTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error
	Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error)
	Cleanup(ctx context.Context, now time.Time) error
}

// StringSliceCache defines a cache for string slices.
type StringSliceCache interface {
	Get(ctx context.Context, key string) ([]string, bool, error)
	Set(ctx context.Context, key string, value []string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

type NoopStringSliceCache struct{}

func (NoopStringSliceCache) Get(context.Context, string) ([]string, bool, error) {
	return nil, false, nil
}
func (NoopStringSliceCache) Set(context.Context, string, []string, time.Duration) error { return nil }
func (NoopStringSliceCache) Del(context.Context, string) error                          { return nil }

// AccessTokenDenylist defines operations for denying access tokens by JTI.
type AccessTokenDenylist interface {
	IsDenied(ctx context.Context, jti string) (bool, error)
	Deny(ctx context.Context, jti string, ttl time.Duration) error
}

type NoopAccessTokenDenylist struct{}

func (NoopAccessTokenDenylist) IsDenied(context.Context, string) (bool, error) {
	return false, nil
}
func (NoopAccessTokenDenylist) Deny(context.Context, string, time.Duration) error { return nil }

// Store bundles all repository interfaces.
type Store struct {
	Users        UserRepository
	RefreshToken RefreshTokenRepository
	Sessions     SessionRepository
	RBAC         RBACRepository
	MFA          MFARepository
	Identity     IdentityRepository
	Audit        AuditRepository
	EmailToken   EmailTokenRepository
}
