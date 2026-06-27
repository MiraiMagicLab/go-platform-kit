package admin_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/admin"
)

func TestBanUserRevokesTokensAndIncrementsVersion(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "u@example.com"})
	refresh := testmem.NewRefreshTokens()
	svc := admin.NewUserAdminService(users, refresh)

	until := time.Now().Add(time.Hour)
	require.NoError(t, svc.BanUser(context.Background(), userID, until, "abuse"))

	u, err := users.GetByID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, 1, u.TokenVersion)
	require.NotNil(t, u.BannedUntil)
}

func TestUnbanUser(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	until := time.Now().Add(time.Hour)
	users.SetUser(userID, domain.User{ID: userID, Email: "u@example.com"})
	_ = users.SetBan(context.Background(), userID, &until, "temp")

	svc := admin.NewUserAdminService(users, testmem.NewRefreshTokens())
	require.NoError(t, svc.UnbanUser(context.Background(), userID))

	u, err := users.GetByID(context.Background(), userID)
	require.NoError(t, err)
	require.Nil(t, u.BannedUntil)
}

func TestDeleteUserSoftDeletesAndRevokes(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "u@example.com"})
	refresh := testmem.NewRefreshTokens()
	_, _ = refresh.Create(context.Background(), userID, uuid.New(), "hash", time.Now().Add(time.Hour), "", "", "")

	svc := admin.NewUserAdminService(users, refresh)
	require.NoError(t, svc.DeleteUser(context.Background(), userID))

	u, err := users.GetByID(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, u.IsDeleted())
	require.Equal(t, 1, u.TokenVersion)
}
