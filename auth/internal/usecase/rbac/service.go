package rbac

import (
	"context"
	"fmt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"time"

	"github.com/google/uuid"
)

// RBACService manages roles, permissions, and their assignments.
type RBACService struct {
	repo     ports.RBACRepository
	cache    ports.StringSliceCache
	cacheTTL time.Duration
}

func NewRBACService(repo ports.RBACRepository, cache ports.StringSliceCache, cacheTTL time.Duration) *RBACService {
	if cache == nil {
		cache = ports.NoopStringSliceCache{}
	}
	return &RBACService{repo: repo, cache: cache, cacheTTL: cacheTTL}
}

func (s *RBACService) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	return s.repo.CreateRole(ctx, name)
}

func (s *RBACService) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	return s.repo.CreatePermission(ctx, name)
}

func (s *RBACService) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if err := s.repo.AssignPermissionsToRole(ctx, roleID, permissionIDs); err != nil {
		return err
	}
	userIDs, err := s.repo.ListUserIDsByRole(ctx, roleID)
	if err != nil {
		return err
	}
	for _, uid := range userIDs {
		_ = s.cache.Del(ctx, userPermCacheKey(uid))
	}
	return nil
}

func (s *RBACService) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if err := s.repo.AssignRolesToUser(ctx, userID, roleIDs); err != nil {
		return err
	}
	_ = s.cache.Del(ctx, userPermCacheKey(userID))
	return nil
}

func (s *RBACService) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	key := userPermCacheKey(userID)
	if v, ok, err := s.cache.Get(ctx, key); err == nil && ok {
		return v, nil
	}
	perms, err := s.repo.ListUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	_ = s.cache.Set(ctx, key, perms, s.cacheTTL)
	return perms, nil
}

func (s *RBACService) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.repo.ListUserRoles(ctx, userID)
}

// AssignRoleByName assigns a single role to a user by role name.
func (s *RBACService) AssignRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	if roleName == "" {
		return nil
	}
	roleID, err := s.repo.GetRoleIDByName(ctx, roleName)
	if err != nil {
		return err
	}
	return s.AssignRolesToUser(ctx, userID, []uuid.UUID{roleID})
}

func userPermCacheKey(userID uuid.UUID) string {
	return fmt.Sprintf("perm:user:%s", userID.String())
}
