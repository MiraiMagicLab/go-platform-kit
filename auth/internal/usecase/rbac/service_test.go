package rbac_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
)

func TestListUserPermissionsUsesCache(t *testing.T) {
	repo := testmem.NewRBAC()
	cache := testmem.NewStringCache()
	svc := rbac.NewRBACService(repo, cache, time.Minute)

	roleID, err := repo.CreateRole(context.Background(), "editor")
	require.NoError(t, err)
	permID, err := repo.CreatePermission(context.Background(), "posts.write")
	require.NoError(t, err)
	require.NoError(t, repo.AssignPermissionsToRole(context.Background(), roleID, []uuid.UUID{permID}))

	userID := uuid.New()
	require.NoError(t, svc.AssignRolesToUser(context.Background(), userID, []uuid.UUID{roleID}))

	perms, err := svc.ListUserPermissions(context.Background(), userID)
	require.NoError(t, err)
	require.Contains(t, perms, "posts.write")

	cacheKey := "perm:user:" + userID.String()
	cached, ok, err := cache.Get(context.Background(), cacheKey)
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, cached, "posts.write")
}

func TestAssignPermissionsToRoleInvalidatesUserCache(t *testing.T) {
	repo := testmem.NewRBAC()
	cache := testmem.NewStringCache()
	svc := rbac.NewRBACService(repo, cache, time.Minute)

	roleID, _ := repo.CreateRole(context.Background(), "editor")
	userID := uuid.New()
	require.NoError(t, svc.AssignRolesToUser(context.Background(), userID, []uuid.UUID{roleID}))

	_, _ = svc.ListUserPermissions(context.Background(), userID)
	cacheKey := "perm:user:" + userID.String()
	_, ok, _ := cache.Get(context.Background(), cacheKey)
	require.True(t, ok)

	permID, _ := repo.CreatePermission(context.Background(), "posts.edit")
	require.NoError(t, svc.AssignPermissionsToRole(context.Background(), roleID, []uuid.UUID{permID}))

	_, ok, _ = cache.Get(context.Background(), cacheKey)
	require.False(t, ok)
}

func TestAssignRoleByName(t *testing.T) {
	repo := testmem.NewRBAC()
	svc := rbac.NewRBACService(repo, testmem.NewStringCache(), time.Minute)

	_, err := repo.CreateRole(context.Background(), "moderator")
	require.NoError(t, err)

	userID := uuid.New()
	require.NoError(t, svc.AssignRoleByName(context.Background(), userID, "moderator"))

	roles, err := svc.ListUserRoles(context.Background(), userID)
	require.NoError(t, err)
	require.Contains(t, roles, "moderator")
}

func TestAssignRoleByNameEmptyIsNoop(t *testing.T) {
	svc := rbac.NewRBACService(testmem.NewRBAC(), testmem.NewStringCache(), time.Minute)
	require.NoError(t, svc.AssignRoleByName(context.Background(), uuid.New(), ""))
}
