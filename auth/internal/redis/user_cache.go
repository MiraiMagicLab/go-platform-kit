package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
)

const userAuthKeyPrefix = "auth:user:"

// UserAuthCache caches user auth state to reduce Postgres reads on JWT middleware.
type UserAuthCache struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewUserAuthCache returns a Redis-backed user auth cache, or nil when rdb is nil.
func NewUserAuthCache(rdb *redis.Client, ttl time.Duration) *UserAuthCache {
	if rdb == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &UserAuthCache{rdb: rdb, ttl: ttl}
}

func (c *UserAuthCache) key(userID uuid.UUID) string {
	return userAuthKeyPrefix + userID.String()
}

// Get returns a cached user auth snapshot when present.
func (c *UserAuthCache) Get(ctx context.Context, userID uuid.UUID) (domain.User, bool, error) {
	if c == nil || c.rdb == nil {
		return domain.User{}, false, nil
	}
	raw, err := c.rdb.Get(ctx, c.key(userID)).Bytes()
	if err != nil {
		return domain.User{}, false, nil
	}
	var u domain.User
	if err := json.Unmarshal(raw, &u); err != nil {
		return domain.User{}, false, err
	}
	return u, true, nil
}

// Set stores the user auth snapshot with TTL.
func (c *UserAuthCache) Set(ctx context.Context, user domain.User) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	b, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, c.key(user.ID), b, c.ttl).Err()
}

// Del removes a cached user snapshot.
func (c *UserAuthCache) Del(ctx context.Context, userID uuid.UUID) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Del(ctx, c.key(userID)).Err()
}
