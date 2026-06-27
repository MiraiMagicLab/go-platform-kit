package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Recovery returns Gin middleware that converts panics into a stable internal error response.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				c.Abort()
				FailCode(c, http.StatusInternalServerError, CodeInternal, nil)
			}
		}()
		c.Next()
	}
}
