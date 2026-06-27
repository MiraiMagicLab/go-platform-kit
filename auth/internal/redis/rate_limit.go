package redis

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimiter provides distributed rate limiting backed by Redis.
type RateLimiter struct {
	rdb *redis.Client
}

// NewRateLimiter returns a RateLimiter for rdb, or nil when rdb is nil.
func NewRateLimiter(rdb *redis.Client) *RateLimiter {
	if rdb == nil {
		return nil
	}
	return &RateLimiter{rdb: rdb}
}

// Incr increments the counter for key and sets expiry on first hit in the window.
func (l *RateLimiter) Incr(c *gin.Context, key string, window time.Duration) (int64, error) {
	if l == nil || l.rdb == nil {
		return 0, redis.Nil
	}
	ctx := c.Request.Context()
	n, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		if err := l.rdb.Expire(ctx, key, window).Err(); err != nil {
			return n, err
		}
	}
	return n, nil
}
