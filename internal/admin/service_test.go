package admin_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/internal/admin"
	"github.com/MiraiMagicLab/go-platform-kit/internal/mocks"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

func TestUserAdminService_BanUser(t *testing.T) {
	userID := uuid.New()
	banUntil := time.Now().Add(24 * time.Hour)
	reason := "violation"

	users := &mocks.UserRepoMock{
		SetBanFunc: func(ctx context.Context, uid uuid.UUID, until *time.Time, r string) error {
			assert.Equal(t, userID, uid)
			assert.Equal(t, banUntil, *until)
			assert.Equal(t, reason, r)
			return nil
		},
		IncrementTokenVersionFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}

	svc := admin.NewUserAdminService(users, refresh)
	err := svc.BanUser(context.Background(), userID, banUntil, reason)

	require.NoError(t, err)
	assert.Len(t, users.IncrementTokenVersionCalls, 1)
	assert.Len(t, refresh.RevokeAllForUserCalls, 1)
}

func TestUserAdminService_UnbanUser(t *testing.T) {
	userID := uuid.New()

	users := &mocks.UserRepoMock{
		SetBanFunc: func(ctx context.Context, uid uuid.UUID, until *time.Time, reason string) error {
			assert.Equal(t, userID, uid)
			assert.Nil(t, until)
			assert.Empty(t, reason)
			return nil
		},
	}

	svc := admin.NewUserAdminService(users, nil)
	err := svc.UnbanUser(context.Background(), userID)

	require.NoError(t, err)
}

func TestUserAdminService_DeleteUser(t *testing.T) {
	userID := uuid.New()

	users := &mocks.UserRepoMock{
		IncrementTokenVersionFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
		SoftDeleteFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}

	svc := admin.NewUserAdminService(users, refresh)
	err := svc.DeleteUser(context.Background(), userID)

	require.NoError(t, err)
	assert.Len(t, users.IncrementTokenVersionCalls, 1)
	assert.Len(t, refresh.RevokeAllForUserCalls, 1)
}

func TestUserAdminService_ListUsers(t *testing.T) {
	expectedUsers := []domain.User{
		{ID: uuid.New(), Email: "test1@example.com"},
		{ID: uuid.New(), Email: "test2@example.com"},
	}

	users := &mocks.UserRepoMock{
		ListUsersFunc: func(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error) {
			assert.Equal(t, 1, page)
			assert.Equal(t, 10, pageSize)
			return expectedUsers, 2, nil
		},
	}

	svc := admin.NewUserAdminService(users, nil)
	result, total, err := svc.ListUsers(context.Background(), 1, 10, ports.ListUsersFilter{})

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, 2, total)
}
