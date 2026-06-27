package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// Ensure RedisStringSliceCache implements ports.StringSliceCache at compile time.
var _ ports.StringSliceCache = (*RedisStringSliceCache)(nil)

// RedisClient defines the minimal Redis operations needed.
type RedisClient interface {
	Get(ctx context.Context, key string) *RedisStringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *RedisStatusCmd
	Del(ctx context.Context, keys ...string) *RedisIntCmd
}

// RedisStringSliceCache implements ports.StringSliceCache using Redis.
type RedisStringSliceCache struct {
	rdb RedisClient
}

// NewRedisStringSliceCache creates a Redis-backed StringSliceCache. Returns nil if rdb is nil.
func NewRedisStringSliceCache(rdb RedisClient) *RedisStringSliceCache {
	if rdb == nil {
		return nil
	}
	return &RedisStringSliceCache{rdb: rdb}
}

// Get retrieves a cached string slice by key. Returns (nil, false, nil) on cache miss.
func (c *RedisStringSliceCache) Get(ctx context.Context, key string) ([]string, bool, error) {
	if c == nil || c.rdb == nil {
		return nil, false, nil
	}
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		return nil, false, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(val), &out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// Set stores a string slice in Redis with the given TTL.
func (c *RedisStringSliceCache) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, string(b), ttl).Err()
}

// Del removes a cached key from Redis.
func (c *RedisStringSliceCache) Del(ctx context.Context, key string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Del(ctx, key).Err()
}

// RedisAccessTokenDenylist implements ports.AccessTokenDenylist using Redis.
var _ ports.AccessTokenDenylist = (*RedisAccessTokenDenylist)(nil)

// RedisAccessTokenDenylist implements ports.AccessTokenDenylist using Redis key-value pairs.
type RedisAccessTokenDenylist struct {
	rdb RedisClient
}

// NewRedisAccessTokenDenylist creates a Redis-backed token denylist. Returns nil if rdb is nil.
func NewRedisAccessTokenDenylist(rdb RedisClient) *RedisAccessTokenDenylist {
	if rdb == nil {
		return nil
	}
	return &RedisAccessTokenDenylist{rdb: rdb}
}

// IsDenied returns true if the given JTI exists in the denylist.
func (d *RedisAccessTokenDenylist) IsDenied(ctx context.Context, jti string) (bool, error) {
	if d == nil || d.rdb == nil {
		return false, nil
	}
	_, err := d.rdb.Get(ctx, "deny:access:"+jti).Result()
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Deny adds a JTI to the denylist with a TTL matching the token's remaining lifetime.
func (d *RedisAccessTokenDenylist) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if d == nil || d.rdb == nil {
		return nil
	}
	return d.rdb.Set(ctx, "deny:access:"+jti, "1", ttl).Err()
}

// RedisStringCmd represents a Redis GET result.
type RedisStringCmd struct {
	val string
	err error
}

// Result returns the stored value and any error from the GET command.
func (c *RedisStringCmd) Result() (string, error) { return c.val, c.err }

// RedisStatusCmd represents a Redis SET result.
type RedisStatusCmd struct {
	err error
}

// Err returns any error from the SET command.
func (c *RedisStatusCmd) Err() error { return c.err }

// RedisIntCmd represents a Redis DEL result.
type RedisIntCmd struct {
	err error
}

// Err returns any error from the DEL command.
func (c *RedisIntCmd) Err() error { return c.err }
