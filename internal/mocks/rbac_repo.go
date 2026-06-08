package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.RBACRepository = (*RBACRepoMock)(nil)

// RBACRepoMock is a mock implementation of ports.RBACRepository for testing.
type RBACRepoMock struct {
	CreateRoleFunc              func(ctx context.Context, name string) (uuid.UUID, error)
	CreatePermissionFunc        func(ctx context.Context, name string) (uuid.UUID, error)
	AssignPermissionsToRoleFunc func(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
	AssignRolesToUserFunc       func(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	ListUserPermissionsFunc     func(ctx context.Context, userID uuid.UUID) ([]string, error)
	ListUserIDsByRoleFunc       func(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)
	ListUserRolesFunc           func(ctx context.Context, userID uuid.UUID) ([]string, error)
}

func (m *RBACRepoMock) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	if m.CreateRoleFunc != nil {
		return m.CreateRoleFunc(ctx, name)
	}
	return uuid.New(), nil
}

func (m *RBACRepoMock) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	if m.CreatePermissionFunc != nil {
		return m.CreatePermissionFunc(ctx, name)
	}
	return uuid.New(), nil
}

func (m *RBACRepoMock) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if m.AssignPermissionsToRoleFunc != nil {
		return m.AssignPermissionsToRoleFunc(ctx, roleID, permissionIDs)
	}
	return nil
}

func (m *RBACRepoMock) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if m.AssignRolesToUserFunc != nil {
		return m.AssignRolesToUserFunc(ctx, userID, roleIDs)
	}
	return nil
}

func (m *RBACRepoMock) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m.ListUserPermissionsFunc != nil {
		return m.ListUserPermissionsFunc(ctx, userID)
	}
	return nil, nil
}

func (m *RBACRepoMock) ListUserIDsByRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	if m.ListUserIDsByRoleFunc != nil {
		return m.ListUserIDsByRoleFunc(ctx, roleID)
	}
	return nil, nil
}

func (m *RBACRepoMock) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if m.ListUserRolesFunc != nil {
		return m.ListUserRolesFunc(ctx, userID)
	}
	return nil, nil
}
