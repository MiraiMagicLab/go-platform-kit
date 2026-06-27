package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

var _ store.RBACRepository = (*RBACAdapter)(nil)

// RBACAdapter wraps *RBACRepo to implement store.RBACRepository.
type RBACAdapter struct {
	repo *RBACRepo
}

func NewRBACAdapter(repo *RBACRepo) *RBACAdapter {
	return &RBACAdapter{repo: repo}
}

func (a *RBACAdapter) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	return a.repo.CreateRole(ctx, name)
}

func (a *RBACAdapter) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	return a.repo.CreatePermission(ctx, name)
}

func (a *RBACAdapter) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	return a.repo.AssignPermissionsToRole(ctx, roleID, permissionIDs)
}

func (a *RBACAdapter) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return a.repo.AssignRolesToUser(ctx, userID, roleIDs)
}

func (a *RBACAdapter) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return a.repo.ListUserPermissions(ctx, userID)
}

func (a *RBACAdapter) ListUserIDsByRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	return a.repo.ListUserIDsByRole(ctx, roleID)
}

func (a *RBACAdapter) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return a.repo.ListUserRoles(ctx, userID)
}
