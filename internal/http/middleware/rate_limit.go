package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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
func SensitiveRateLimit(redisClient interface{}, mem *InMemoryRateLimiter, prefix string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := clientIP(c)
		key := prefix + ":" + ip

		// Try Redis first if available
		if rc, ok := redisClient.(interface {
			Incr(ctx *gin.Context, key string, window time.Duration) (int64, error)
		}); ok && rc != nil {
			count, err := rc.Incr(c, key, window)
			if err == nil && count > int64(limit) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
				c.Abort()
				return
			}
			if err == nil {
				c.Next()
				return
			}
		}

		// Fallback to in-memory
		if mem != nil && !mem.Allow(key, limit, window) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
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
