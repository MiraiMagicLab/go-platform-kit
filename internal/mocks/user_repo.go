package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// Ensure UserRepoMock implements ports.UserRepository at compile time.
var _ ports.UserRepository = (*UserRepoMock)(nil)

// UserRepoMock is a mock implementation of ports.UserRepository for testing.
type UserRepoMock struct {
	mu sync.RWMutex

	CreateFunc                func(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	CreateOAuthUserFunc       func(ctx context.Context, email, passwordHash string) (uuid.UUID, error)
	GetByEmailFunc            func(ctx context.Context, email string) (domain.User, error)
	GetByIDFunc               func(ctx context.Context, id uuid.UUID) (domain.User, error)
	IncrementTokenVersionFunc func(ctx context.Context, userID uuid.UUID) error
	SetPasswordFunc           func(ctx context.Context, userID uuid.UUID, passwordHash string) error
	SetEmailVerifiedFunc      func(ctx context.Context, userID uuid.UUID, verified bool) error
	SetBanFunc                func(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error
	IncrementFailedLoginFunc  func(ctx context.Context, userID uuid.UUID) error
	ResetFailedLoginFunc      func(ctx context.Context, userID uuid.UUID) error
	SetLockFunc               func(ctx context.Context, userID uuid.UUID, until time.Time) error
	SoftDeleteFunc            func(ctx context.Context, userID uuid.UUID) error
	ListUsersFunc             func(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error)

	// Call tracking
	CreateCalls                []CreateCall
	IncrementTokenVersionCalls []uuid.UUID
}

type CreateCall struct {
	Email        string
	PasswordHash string
}

func (m *UserRepoMock) Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	m.mu.Lock()
	m.CreateCalls = append(m.CreateCalls, CreateCall{Email: email, PasswordHash: passwordHash})
	m.mu.Unlock()
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, email, passwordHash)
	}
	return uuid.New(), nil
}

func (m *UserRepoMock) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	if m.CreateOAuthUserFunc != nil {
		return m.CreateOAuthUserFunc(ctx, email, passwordHash)
	}
	return uuid.New(), nil
}

func (m *UserRepoMock) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	if m.GetByEmailFunc != nil {
		return m.GetByEmailFunc(ctx, email)
	}
	return domain.User{}, nil
}

func (m *UserRepoMock) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return domain.User{}, nil
}

func (m *UserRepoMock) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	m.IncrementTokenVersionCalls = append(m.IncrementTokenVersionCalls, userID)
	m.mu.Unlock()
	if m.IncrementTokenVersionFunc != nil {
		return m.IncrementTokenVersionFunc(ctx, userID)
	}
	return nil
}

func (m *UserRepoMock) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	if m.SetPasswordFunc != nil {
		return m.SetPasswordFunc(ctx, userID, passwordHash)
	}
	return nil
}

func (m *UserRepoMock) SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	if m.SetEmailVerifiedFunc != nil {
		return m.SetEmailVerifiedFunc(ctx, userID, verified)
	}
	return nil
}

func (m *UserRepoMock) SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error {
	if m.SetBanFunc != nil {
		return m.SetBanFunc(ctx, userID, bannedUntil, reason)
	}
	return nil
}

func (m *UserRepoMock) IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error {
	if m.IncrementFailedLoginFunc != nil {
		return m.IncrementFailedLoginFunc(ctx, userID)
	}
	return nil
}

func (m *UserRepoMock) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	if m.ResetFailedLoginFunc != nil {
		return m.ResetFailedLoginFunc(ctx, userID)
	}
	return nil
}

func (m *UserRepoMock) SetLock(ctx context.Context, userID uuid.UUID, until time.Time) error {
	if m.SetLockFunc != nil {
		return m.SetLockFunc(ctx, userID, until)
	}
	return nil
}

func (m *UserRepoMock) SoftDelete(ctx context.Context, userID uuid.UUID) error {
	if m.SoftDeleteFunc != nil {
		return m.SoftDeleteFunc(ctx, userID)
	}
	return nil
}

func (m *UserRepoMock) ListUsers(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error) {
	if m.ListUsersFunc != nil {
		return m.ListUsersFunc(ctx, page, pageSize, filter)
	}
	return nil, 0, nil
}
