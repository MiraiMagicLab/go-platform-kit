package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const ctxRequestIDKey = "request_id"

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-Id")
		if rid == "" {
			rid = uuid.NewString()
		}
		c.Set(ctxRequestIDKey, rid)
		c.Writer.Header().Set("X-Request-Id", rid)
		c.Next()
	}
}

func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		rid, _ := c.Get(ctxRequestIDKey)
		log.Printf("rid=%v method=%s path=%s status=%d latency_ms=%d ip=%s",
			rid, c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start).Milliseconds(), c.ClientIP())
	}
}
