package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tienh/authsvc/internal/db"
)

type StringSliceCache interface {
	Get(ctx context.Context, key string) ([]string, bool, error)
	Set(ctx context.Context, key string, value []string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

type NoopStringSliceCache struct{}

func (NoopStringSliceCache) Get(context.Context, string) ([]string, bool, error) {
	return nil, false, nil
}
func (NoopStringSliceCache) Set(context.Context, string, []string, time.Duration) error {
	return nil
}
func (NoopStringSliceCache) Del(context.Context, string) error { return nil }

type RedisStringSliceCache struct {
	rdb db.RedisClient
}

func NewRedisStringSliceCache(rdb db.RedisClient) *RedisStringSliceCache {
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
