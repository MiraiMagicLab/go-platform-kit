package response

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ApiResponse struct {
	Success bool                   `json:"success"`
	Code    string                 `json:"code"`
	Params  map[string]interface{} `json:"params,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
}

func Success(c *gin.Context, status int, code string, data interface{}, params map[string]interface{}) {
	if code == "" {
		code = "success"
	}
	c.JSON(status, ApiResponse{
		Success: true,
		Code:    code,
		Params:  params,
		Data:    data,
	})
}

func Fail(c *gin.Context, status int, code string, params map[string]interface{}) {
	if code == "" {
		code = "system.unknown_error"
	}
	c.JSON(status, ApiResponse{
		Success: false,
		Code:    code,
		Params:  params,
	})
}

// FailCode returns an error response with stable code for client i18n.
func FailCode(c *gin.Context, status int, code string, params map[string]interface{}) {
	if code == "" {
		code = "system.unknown_error"
	}
	c.JSON(status, ApiResponse{
		Success: false,
		Code:    code,
		Params:  params,
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

// PaginationMeta describes common limit/offset pagination.
type PaginationMeta struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

type PaginationResult struct {
	Records    interface{}    `json:"records"`
	Pagination PaginationMeta `json:"pagination"`
}

// Pagination returns a consistent paginated response payload.
func Pagination(c *gin.Context, status int, records interface{}, limit, offset int, total int64) {
	c.JSON(status, ApiResponse{
		Success: true,
		Code:    "success",
		Data: PaginationResult{
			Records: records,
			Pagination: PaginationMeta{
				Limit:  limit,
				Offset: offset,
				Total:  total,
			},
		},
	})
}

// CursorPaginationMeta describes cursor-based pagination metadata.
type CursorPaginationMeta struct {
	NextCursor string `json:"nextCursor" example:"opaque_string"`
	HasMore    bool   `json:"hasMore"`
}

type CursorPaginationResult struct {
	Records    interface{}          `json:"records"`
	Pagination CursorPaginationMeta `json:"pagination"`
}

// CursorPagination returns a consistent cursor-based paginated response.
func CursorPagination(c *gin.Context, status int, records interface{}, nextCursor string, hasMore bool) {
	c.JSON(status, ApiResponse{
		Success: true,
		Code:    "success",
		Data: CursorPaginationResult{
			Records: records,
			Pagination: CursorPaginationMeta{
				NextCursor: nextCursor,
				HasMore:    hasMore,
			},
		},
	})
}
