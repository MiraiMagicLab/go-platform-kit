package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/ports"
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

func NewRedisStringSliceCache(rdb RedisClient) *RedisStringSliceCache {
	if rdb == nil {
		return nil
	}
	return &RedisStringSliceCache{rdb: rdb}
}

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

func (c *RedisStringSliceCache) Del(ctx context.Context, key string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Del(ctx, key).Err()
}

// RedisAccessTokenDenylist implements ports.AccessTokenDenylist using Redis.
var _ ports.AccessTokenDenylist = (*RedisAccessTokenDenylist)(nil)

type RedisAccessTokenDenylist struct {
	rdb RedisClient
}

func NewRedisAccessTokenDenylist(rdb RedisClient) *RedisAccessTokenDenylist {
	if rdb == nil {
		return nil
	}
	return &RedisAccessTokenDenylist{rdb: rdb}
}

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

func (d *RedisAccessTokenDenylist) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if d == nil || d.rdb == nil {
		return nil
	}
	return d.rdb.Set(ctx, "deny:access:"+jti, "1", ttl).Err()
}

// Redis command result types (minimal wrappers to avoid importing go-redis directly).
type RedisStringCmd struct {
	val string
	err error
}

func (c *RedisStringCmd) Result() (string, error) { return c.val, c.err }

type RedisStatusCmd struct {
	err error
}

func (c *RedisStatusCmd) Err() error { return c.err }

type RedisIntCmd struct {
	err error
}

func (c *RedisIntCmd) Err() error { return c.err }
