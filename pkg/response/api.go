package response

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApiResponse struct {
	Success     bool                   `json:"success"`
	CodeMessage string                 `json:"codeMessage"`
	Message     string                 `json:"message,omitempty"`
	Params      map[string]interface{} `json:"params,omitempty"`
	Data        interface{}            `json:"data,omitempty"`
}

func Success(c *gin.Context, status int, code, message string, data interface{}, params map[string]interface{}) {
	if code == "" {
		code = "common.ok"
	}
	c.JSON(status, ApiResponse{
		Success:     true,
		CodeMessage: code,
		Message:     message,
		Params:      params,
		Data:        data,
	})
}

func Fail(c *gin.Context, status int, code, fallbackMessage string, params map[string]interface{}) {
	if fallbackMessage == "" {
		fallbackMessage = DefaultMessage(code)
	}
	if code == "" {
		code = "common.unknown_error"
	}
	c.JSON(status, ApiResponse{
		Success:     false,
		CodeMessage: code,
		Message:     fallbackMessage,
		Params:      params,
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

// FailNotFound responds with 404 and the standard not-found code (same shape as other FailCode responses).
func FailNotFound(c *gin.Context) {
	FailCode(c, http.StatusNotFound, CodeCommonNotFound)
}
