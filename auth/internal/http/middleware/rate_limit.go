package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// InMemoryRateLimiter provides in-memory rate limiting as a fallback.
type InMemoryRateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientRate
}

type clientRate struct {
	count   int
	resetAt time.Time
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter.
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		clients: make(map[string]*clientRate),
	}
}

// Allow reports whether a request with the given key is allowed under the rate limit.
// It returns true if the request is within the limit for the current window, false otherwise.
func (l *InMemoryRateLimiter) Allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cr, ok := l.clients[key]
	if !ok || now.After(cr.resetAt) {
		l.clients[key] = &clientRate{count: 1, resetAt: now.Add(window)}
		return true
	}
	if cr.count >= limit {
		return false
	}
	cr.count++
	return true
}

// RedisRateLimiter defines the interface for Redis-based rate limiting.
type RedisRateLimiter interface {
	Incr(ctx *gin.Context, key string, window time.Duration) (int64, error)
}

// SensitiveRateLimit returns middleware that rate-limits sensitive endpoints.
// It tries Redis first (distributed), then falls back to in-memory.
func SensitiveRateLimit(redisClient RedisRateLimiter, mem *InMemoryRateLimiter, prefix string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := clientIP(c)
		key := prefix + ":" + ip

		if redisClient != nil {
			count, err := redisClient.Incr(c, key, window)
			if err == nil && count > int64(limit) {
				httpx.FailCode(c, http.StatusTooManyRequests, apperrors.CodeRateLimited, nil)
				c.Abort()
				return
			}
			if err == nil {
				c.Next()
				return
			}
		}

		if mem != nil && !mem.Allow(key, limit, window) {
			httpx.FailCode(c, http.StatusTooManyRequests, apperrors.CodeRateLimited, nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

func clientIP(c *gin.Context) string {
	ip := c.ClientIP()
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
