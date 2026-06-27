package db

import (
	"context"
	"time"
)

// RedisClient defines the minimal Redis operations needed.
type RedisClient interface {
	// Get retrieves the value associated with the given key.
	Get(ctx context.Context, key string) *RedisStringCmd
	// Set stores a value under the given key with an optional expiration duration.
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *RedisStatusCmd
	// Del removes one or more keys, returning the number of keys removed.
	Del(ctx context.Context, keys ...string) *RedisIntCmd
	// Close terminates the underlying connection.
	Close() error
}

// RedisStringCmd represents a Redis GET result.
type RedisStringCmd struct {
	val string
	err error
}

// Result returns the stored value and any error from the GET command.
func (c *RedisStringCmd) Result() (string, error) { return c.val, c.err }

// Err returns any error from the GET command.
func (c *RedisStringCmd) Err() error { return c.err }

// RedisStatusCmd represents a Redis SET result.
type RedisStatusCmd struct {
	err error
}

// Err returns any error from the SET command.
func (c *RedisStatusCmd) Err() error { return c.err }

// RedisIntCmd represents a Redis DEL result.
type RedisIntCmd struct {
	val int64
	err error
}

// Err returns any error from the DEL command.
func (c *RedisIntCmd) Err() error { return c.err }
