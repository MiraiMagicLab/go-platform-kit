package redis

import (
	"context"
	"encoding/json"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	_ ports.StringSliceCache    = (*StringSliceCache)(nil)
	_ ports.AccessTokenDenylist = (*AccessTokenDenylist)(nil)
)

// StringSliceCache implements ports.StringSliceCache using go-redis.
type StringSliceCache struct {
	rdb *redis.Client
}

func NewStringSliceCache(rdb *redis.Client) *StringSliceCache {
	if rdb == nil {
		return nil
	}
	return &StringSliceCache{rdb: rdb}
}

func (c *StringSliceCache) Get(ctx context.Context, key string) ([]string, bool, error) {
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

func (c *StringSliceCache) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, string(b), ttl).Err()
}

func (c *StringSliceCache) Del(ctx context.Context, key string) error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Del(ctx, key).Err()
}

// AccessTokenDenylist implements ports.AccessTokenDenylist using go-redis.
type AccessTokenDenylist struct {
	rdb *redis.Client
}

func NewAccessTokenDenylist(rdb *redis.Client) *AccessTokenDenylist {
	if rdb == nil {
		return nil
	}
	return &AccessTokenDenylist{rdb: rdb}
}

func (d *AccessTokenDenylist) IsDenied(ctx context.Context, jti string) (bool, error) {
	if d == nil || d.rdb == nil {
		return false, nil
	}
	_, err := d.rdb.Get(ctx, "deny:access:"+jti).Result()
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (d *AccessTokenDenylist) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if d == nil || d.rdb == nil {
		return nil
	}
	return d.rdb.Set(ctx, "deny:access:"+jti, "1", ttl).Err()
}
