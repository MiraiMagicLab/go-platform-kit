package db

import (
	"context"
	"time"
)

// RedisClient defines the minimal Redis operations needed.
type RedisClient interface {
	Get(ctx context.Context, key string) *RedisStringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *RedisStatusCmd
	Del(ctx context.Context, keys ...string) *RedisIntCmd
	Close() error
}

// RedisStringCmd represents a Redis GET result.
type RedisStringCmd struct {
	val string
	err error
}

func (c *RedisStringCmd) Result() (string, error) { return c.val, c.err }
func (c *RedisStringCmd) Err() error              { return c.err }

// RedisStatusCmd represents a Redis SET result.
type RedisStatusCmd struct {
	err error
}

func (c *RedisStatusCmd) Err() error { return c.err }

// RedisIntCmd represents a Redis DEL result.
type RedisIntCmd struct {
	val int64
	err error
}

func (c *RedisIntCmd) Err() error { return c.err }
