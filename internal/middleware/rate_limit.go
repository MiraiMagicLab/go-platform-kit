package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type inMemCounter struct {
	count   int
	expires time.Time
}

type InMemoryRateLimiter struct {
	mu              sync.Mutex
	store           map[string]inMemCounter
	lastCleanup     time.Time
	cleanupInterval time.Duration
}

func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		store:           map[string]inMemCounter{},
		lastCleanup:     time.Now(),
		cleanupInterval: 5 * time.Minute,
	}
}

func (l *InMemoryRateLimiter) cleanupLocked(now time.Time) {
	for key, v := range l.store {
		if now.After(v.expires) {
			delete(l.store, key)
		}
	}
	l.lastCleanup = now
}

func (l *InMemoryRateLimiter) Allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastCleanup) > l.cleanupInterval {
		l.cleanupLocked(now)
	}
	v, ok := l.store[key]
	if !ok || now.After(v.expires) {
		l.store[key] = inMemCounter{count: 1, expires: now.Add(window)}
		return true
	}
	if v.count >= limit {
		return false
	}
	v.count++
	l.store[key] = v
	return true
}

func SensitiveRateLimit(redisClient *redis.Client, mem *InMemoryRateLimiter, prefix string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limit <= 0 {
			c.Next()
			return
		}
		key := fmt.Sprintf("%s:%s", prefix, c.ClientIP())
		allowed := false

		if redisClient != nil {
			ctx := c.Request.Context()
			count, err := redisClient.Incr(ctx, key).Result()
			if err == nil {
				if count == 1 {
					_ = redisClient.Expire(ctx, key, window).Err()
				}
				allowed = count <= int64(limit)
			}
		}
		if !allowed && mem != nil {
			allowed = mem.Allow(key, limit, window)
		}

		if !allowed {
			response.FailCode(c, http.StatusTooManyRequests, response.CodeCommonTooManyRequests, nil)
			c.Abort()
			return
		}
		c.Next()
	}
}
