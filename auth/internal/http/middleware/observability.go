package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
)

var platformLogger log.Logger = log.Noop{}

// SetLogger configures the logger used by auth HTTP middleware.
func SetLogger(l log.Logger) {
	if l == nil {
		platformLogger = log.Noop{}
		return
	}
	platformLogger = l
}

// RequestID returns middleware that injects/propagates X-Request-Id header.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-Id")
		if id == "" {
			id = uuid.New().String()
		}
		c.Set("request_id", id)
		c.Writer.Header().Set("X-Request-Id", id)
		c.Next()
	}
}

// AccessLog returns middleware that logs requests using the configured platform logger.
func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		platformLogger.Info("http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", c.ClientIP(),
			"request_id", c.GetString("request_id"),
		)
	}
}

// AccessLogSimple returns middleware that only logs error responses.
func AccessLogSimple() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		if c.Writer.Status() >= 400 {
			platformLogger.Warn("http error",
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"status", c.Writer.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"client_ip", c.ClientIP(),
				"request_id", c.GetString("request_id"),
			)
		}
	}
}
