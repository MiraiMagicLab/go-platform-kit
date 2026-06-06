package middleware

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const ctxRequestIDKey = "request_id"

// RequestID injects or reads a request ID (X-Request-Id header).
// If the client sends X-Request-Id, it is used as-is for tracing.
// Otherwise, a new UUID is generated.
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

// accessLogEntry is the structured log format for all auth requests.
type accessLogEntry struct {
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`
	// AuthErrorCode is set when the response contains an auth error code
	// (e.g. auth.invalid_credentials, auth.email.not_verified).
	AuthErrorCode string `json:"auth_error_code,omitempty"`
}

// AccessLog logs all requests in structured JSON format to stdout.
// It is safe to use in production as sensitive fields are never logged.
func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		rid, _ := c.Get(ctxRequestIDKey)
		requestID, _ := rid.(string)

		// Extract auth error code from response context (set by handlers)
		errCode, _ := c.Get("auth_error_code")
		authErrorCode, _ := errCode.(string)

		entry := accessLogEntry{
			RequestID:     requestID,
			Method:        c.Request.Method,
			Path:          c.Request.URL.Path,
			Status:        c.Writer.Status(),
			LatencyMs:     time.Since(start).Milliseconds(),
			ClientIP:      c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			AuthErrorCode: authErrorCode,
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		log.Printf("%s", data)
	}
}

// SetAuthErrorCode stores an auth error code in the context for logging.
// Call this in handlers before writing error responses.
func SetAuthErrorCode(c *gin.Context, code string) {
	c.Set("auth_error_code", code)
}

// AccessLogSimple is a lightweight version that only logs errors.
// Use this if AccessLog produces too much output in high-traffic environments.
func AccessLogSimple() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := c.Writer.Status()
		// Only log errors and slow requests (>500ms) to stdout
		if status >= 400 || time.Since(start) > 500*time.Millisecond {
			rid, _ := c.Get(ctxRequestIDKey)
			requestID, _ := rid.(string)
			errCode, _ := c.Get("auth_error_code")
			authErrorCode, _ := errCode.(string)

			path := c.Request.URL.Path
			// Truncate long paths (e.g. with tokens)
			if len(path) > 120 {
				path = path[:120] + "...[TRUNCATED]"
			}

			// Sanitize user agent for brevity
			ua := c.Request.UserAgent()
			if len(ua) > 80 {
				ua = ua[:80] + "..."
			}

			// Structured log format: LEVEL request_id method path status latency_ms ip "user_agent" error_code
			level := "INFO"
			if status >= 500 {
				level = "ERROR"
			} else if status >= 400 {
				level = "WARN"
			}

			var logLine string
			if authErrorCode != "" {
				logLine = level + " " + requestID + " " + c.Request.Method + " " + path + " " +
					itoa(status) + " " + itoa(int(time.Since(start).Milliseconds())) + "ms " +
					c.ClientIP() + " " + ua + " " + authErrorCode
			} else {
				logLine = level + " " + requestID + " " + c.Request.Method + " " + path + " " +
					itoa(status) + " " + itoa(int(time.Since(start).Milliseconds())) + "ms " +
					c.ClientIP() + " " + ua
			}

			// Redact tokens in paths
			logLine = redactTokenParams(logLine)
			log.Print(logLine)
		}
	}
}

// redactTokenParams replaces token/secret values in URL query strings.
func redactTokenParams(s string) string {
	// Match common sensitive query param names and redact their values
	sensitiveParams := []string{"token", "refresh_token", "access_token", "secret", "key", "code", "state"}
	for _, param := range sensitiveParams {
		// Match param=value and replace value with REDACTED
		prefix := param + "="
		if idx := strings.Index(s, prefix); idx != -1 {
			// Find the value start and end
			start := idx + len(prefix)
			end := start
			for end < len(s) && s[end] != ' ' && s[end] != '&' && s[end] != '"' {
				end++
			}
			s = s[:start] + "***REDACTED***" + s[end:]
		}
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + uitoa(uint(-n))
	}
	return uitoa(uint(n))
}

func uitoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
