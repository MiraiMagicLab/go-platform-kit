package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// RBACService manages roles, permissions, and their assignments.
type RBACService struct {
	repo     ports.RBACRepository
	cache    ports.StringSliceCache
	cacheTTL time.Duration
}

// NewRBACService creates an RBACService with optional permission caching. If cache is nil,
// a no-op cache is used. cacheTTL controls how long resolved permissions are cached.
func NewRBACService(repo ports.RBACRepository, cache ports.StringSliceCache, cacheTTL time.Duration) *RBACService {
	if cache == nil {
		cache = ports.NoopStringSliceCache{}
	}
	return &RBACService{repo: repo, cache: cache, cacheTTL: cacheTTL}
}

// CreateRole creates a new role and returns its ID.
func (s *RBACService) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	return s.repo.CreateRole(ctx, name)
}

// CreatePermission creates a new permission and returns its ID.
func (s *RBACService) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	return s.repo.CreatePermission(ctx, name)
}

// AssignPermissionsToRole replaces the role's permissions and invalidates the
// permission cache for all users assigned to that role.
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

// AssignRolesToUser replaces the user's roles and invalidates their permission cache.
func (s *RBACService) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if err := s.repo.AssignRolesToUser(ctx, userID, roleIDs); err != nil {
		return err
	}
	_ = s.cache.Del(ctx, userPermCacheKey(userID))
	return nil
}

// ListUserPermissions returns all permission strings for the user, using the cache
// when available. Results are cached for cacheTTL on cache miss.
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

// ListUserRoles returns all role names assigned to the user.
func (s *RBACService) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.repo.ListUserRoles(ctx, userID)
}

func userPermCacheKey(userID uuid.UUID) string {
	return fmt.Sprintf("perm:user:%s", userID.String())
}
