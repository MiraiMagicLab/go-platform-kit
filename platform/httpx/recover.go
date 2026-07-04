package httpx

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
)

// Recovery returns Gin middleware that converts panics into a stable internal error response.
// If logger is nil, panics are silently recovered without logging.
func Recovery(logger ...log.Logger) gin.HandlerFunc {
	var l log.Logger
	if len(logger) > 0 && logger[0] != nil {
		l = logger[0]
	} else {
		l = log.Noop{}
	}
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				l.Error("panic recovered", "panic", recovered, slog.String("path", c.Request.URL.Path))
				c.Abort()
				FailCode(c, http.StatusInternalServerError, errors.CodeInternal, nil)
			}
		}()
		c.Next()
	}
}
