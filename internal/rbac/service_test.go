package rbac_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/internal/mocks"
	"github.com/MiraiMagicLab/go-platform-kit/internal/rbac"
)

func TestRBACService_CreateRole(t *testing.T) {
	roleID := uuid.New()
	repo := &mocks.RBACRepoMock{
		CreateRoleFunc: func(ctx context.Context, name string) (uuid.UUID, error) {
			assert.Equal(t, "test_role", name)
			return roleID, nil
		},
	}

	svc := rbac.NewRBACService(repo, nil, 30*time.Second)
	id, err := svc.CreateRole(context.Background(), "test_role")

	require.NoError(t, err)
	assert.Equal(t, roleID, id)
}

func TestRBACService_CreatePermission(t *testing.T) {
	permID := uuid.New()
	repo := &mocks.RBACRepoMock{
		CreatePermissionFunc: func(ctx context.Context, name string) (uuid.UUID, error) {
			assert.Equal(t, "test_perm", name)
			return permID, nil
		},
	}

	svc := rbac.NewRBACService(repo, nil, 30*time.Second)
	id, err := svc.CreatePermission(context.Background(), "test_perm")

	require.NoError(t, err)
	assert.Equal(t, permID, id)
}

func TestRBACService_AssignPermissionsToRole(t *testing.T) {
	roleID := uuid.New()
	permIDs := []uuid.UUID{uuid.New(), uuid.New()}
	userID := uuid.New()

	repo := &mocks.RBACRepoMock{
		AssignPermissionsToRoleFunc: func(ctx context.Context, rid uuid.UUID, pids []uuid.UUID) error {
			assert.Equal(t, roleID, rid)
			assert.Equal(t, permIDs, pids)
			return nil
		},
		ListUserIDsByRoleFunc: func(ctx context.Context, rid uuid.UUID) ([]uuid.UUID, error) {
			return []uuid.UUID{userID}, nil
		},
	}
	cache := &mocks.StringSliceCacheMock{}

	svc := rbac.NewRBACService(repo, cache, 30*time.Second)
	err := svc.AssignPermissionsToRole(context.Background(), roleID, permIDs)

	require.NoError(t, err)
}

func TestRBACService_AssignRolesToUser(t *testing.T) {
	userID := uuid.New()
	roleIDs := []uuid.UUID{uuid.New()}

	repo := &mocks.RBACRepoMock{
		AssignRolesToUserFunc: func(ctx context.Context, uid uuid.UUID, rids []uuid.UUID) error {
			assert.Equal(t, userID, uid)
			assert.Equal(t, roleIDs, rids)
			return nil
		},
	}
	cache := &mocks.StringSliceCacheMock{}

	svc := rbac.NewRBACService(repo, cache, 30*time.Second)
	err := svc.AssignRolesToUser(context.Background(), userID, roleIDs)

	require.NoError(t, err)
}

func TestRBACService_ListUserPermissions_CacheHit(t *testing.T) {
	userID := uuid.New()
	expectedPerms := []string{"read", "write"}

	cache := &mocks.StringSliceCacheMock{
		GetFunc: func(ctx context.Context, key string) ([]string, bool, error) {
			return expectedPerms, true, nil
		},
	}

	svc := rbac.NewRBACService(nil, cache, 30*time.Second)
	perms, err := svc.ListUserPermissions(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, expectedPerms, perms)
}

func TestRBACService_ListUserPermissions_CacheMiss(t *testing.T) {
	userID := uuid.New()
	expectedPerms := []string{"read", "write"}

	repo := &mocks.RBACRepoMock{
		ListUserPermissionsFunc: func(ctx context.Context, uid uuid.UUID) ([]string, error) {
			assert.Equal(t, userID, uid)
			return expectedPerms, nil
		},
	}
	cache := &mocks.StringSliceCacheMock{
		GetFunc: func(ctx context.Context, key string) ([]string, bool, error) {
			return nil, false, nil
		},
		SetFunc: func(ctx context.Context, key string, value []string, ttl time.Duration) error {
			assert.Equal(t, expectedPerms, value)
			return nil
		},
	}

	svc := rbac.NewRBACService(repo, cache, 30*time.Second)
	perms, err := svc.ListUserPermissions(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, expectedPerms, perms)
}

func TestRBACService_ListUserRoles(t *testing.T) {
	userID := uuid.New()
	expectedRoles := []string{"admin", "user"}

	repo := &mocks.RBACRepoMock{
		ListUserRolesFunc: func(ctx context.Context, uid uuid.UUID) ([]string, error) {
			assert.Equal(t, userID, uid)
			return expectedRoles, nil
		},
	}

	svc := rbac.NewRBACService(repo, nil, 30*time.Second)
	roles, err := svc.ListUserRoles(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, expectedRoles, roles)
}
