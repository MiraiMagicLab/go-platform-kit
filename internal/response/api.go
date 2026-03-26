package response

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

type ErrorMessage struct {
	ErrorCode string                 `json:"errorCode"`
	Message   string                 `json:"message"`
	Params    map[string]interface{} `json:"params,omitempty"`
}

type ApiResponse struct {
	Success      bool          `json:"success"`
	Message      string        `json:"message,omitempty"`
	ErrorMessage *ErrorMessage `json:"errorMessage,omitempty"`
	Data         interface{}   `json:"data,omitempty"`
}

func Success(c *gin.Context, status int, message string, data interface{}) {
	c.JSON(status, ApiResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func Fail(c *gin.Context, status int, code, fallbackMessage string, params map[string]interface{}) {
	if fallbackMessage == "" {
		fallbackMessage = DefaultMessage(code)
	}
	c.JSON(status, ApiResponse{
		Success: false,
		Message: fallbackMessage,
		ErrorMessage: &ErrorMessage{
			ErrorCode: code,
			Message:   fallbackMessage,
			Params:    params,
		},
	})
}

// FailCode uses default message by error code, supports positional parameters:
// e.g. template "Hello {0}" with args ("Alice").
func FailCode(c *gin.Context, status int, code string, args ...interface{}) {
	msg := RenderMessage(DefaultMessage(code), args...)
	Fail(c, status, code, msg, BuildParams(args...))
}

func BuildParams(args ...interface{}) map[string]interface{} {
	if len(args) == 0 {
		return nil
	}
	params := make(map[string]interface{}, len(args)+1)
	params["args"] = args
	for i, v := range args {
		params[fmt.Sprintf("%d", i)] = v
	}
	return params
}

func RenderMessage(template string, args ...interface{}) string {
	out := template
	for i, v := range args {
		out = strings.ReplaceAll(out, fmt.Sprintf("{%d}", i), fmt.Sprint(v))
	}
	return out
}
