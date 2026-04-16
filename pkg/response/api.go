package response

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApiResponse struct {
	Code   string                 `json:"code"`
	Params map[string]interface{} `json:"params,omitempty"`
	Data   interface{}            `json:"data,omitempty"`
}

func Success(c *gin.Context, status int, code string, data interface{}, params map[string]interface{}) {
	if code == "" {
		code = "success"
	}
	c.JSON(status, ApiResponse{
		Code:   code,
		Params: params,
		Data:   data,
	})
}

func Fail(c *gin.Context, status int, code string, params map[string]interface{}) {
	if code == "" {
		code = "system.unknown_error"
	}
	c.JSON(status, ApiResponse{
		Code:   code,
		Params: params,
	})
}

// FailCode returns an error response with stable code for client i18n.
func FailCode(c *gin.Context, status int, code string, params map[string]interface{}) {
	if code == "" {
		code = "system.unknown_error"
	}
	c.JSON(status, ApiResponse{
		Code:   code,
		Params: params,
	})
}

// FailCodeArgs supports positional parameters like "{0}". Params will contain the args.
func FailCodeArgs(c *gin.Context, status int, code string, args ...interface{}) {
	FailCode(c, status, code, BuildParams(args...))
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

// FailNotFound responds with 404 and the standard not-found code.
func FailNotFound(c *gin.Context) {
	FailCode(c, http.StatusNotFound, CodeCommonNotFound, nil)
}
