package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repository"
)

type RBACService struct {
	repo     repository.RBACRepository
	cache    StringSliceCache
	cacheTTL time.Duration
}

func NewRBACService(repo repository.RBACRepository, cache StringSliceCache, cacheTTL time.Duration) *RBACService {
	if cache == nil {
		cache = NoopStringSliceCache{}
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
	// NOTE: If you want stronger cache invalidation, you can delete keys for all users in role.
	return s.repo.AssignPermissionsToRole(ctx, roleID, permissionIDs)
}

func (s *RBACService) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if err := s.repo.AssignRolesToUser(ctx, userID, roleIDs); err != nil {
		return err
	}
	_ = s.cache.Del(ctx, s.userPermCacheKey(userID))
	return nil
}

func (s *RBACService) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	key := s.userPermCacheKey(userID)
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

func (s *RBACService) userPermCacheKey(userID uuid.UUID) string {
	return fmt.Sprintf("perm:user:%s", userID.String())
}
