package response

import (
	"fmt"
	"net/http"
	"strconv"
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
		code = CodeUnknownError
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
		code = CodeUnknownError
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
	FailCode(c, http.StatusNotFound, CodeNotFound, nil)
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

// OK returns a 200 success response.
func OK(c *gin.Context, data interface{}) {
	Success(c, http.StatusOK, "success", data, nil)
}

// Created returns a 201 success response.
func Created(c *gin.Context, data interface{}) {
	Success(c, http.StatusCreated, "success", data, nil)
}

// StatusToErrorCode maps HTTP status into stable codeMessage strings.
func StatusToErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusInternalServerError:
		return CodeInternal
	default:
		if status >= 400 && status < 500 {
			return CodeBadRequest
		}
		if status >= 500 {
			return CodeInternal
		}
		return CodeUnknownError
	}
}

// FailStatus behaves like Fail and attaches a stable code derived from HTTP status.
func FailStatus(c *gin.Context, status int, params map[string]interface{}) {
	code := StatusToErrorCode(status)
	FailCode(c, status, code, params)
}

// PaginatingQueryRecord is the pagination format: {records, current, size, total}.
type PaginatingQueryRecord struct {
	Records interface{} `json:"records"`
	Current int         `json:"current"`
	Size    int         `json:"size"`
	Total   int         `json:"total"`
}

// PaginateQueryRecord wraps records with {records,current,size,total}.
func PaginateQueryRecord(c *gin.Context, status int, records interface{}, current, size, total int) {
	c.JSON(status, ApiResponse{
		Success: true,
		Code:    "success",
		Data: PaginatingQueryRecord{
			Records: records,
			Current: current,
			Size:    size,
			Total:   total,
		},
	})
}

// ParseLimitOffset reads `limit` + `offset` from query and applies sane bounds.
func ParseLimitOffset(c *gin.Context, defaultLimit, maxLimit int) (limit, offset int) {
	limit = defaultLimit
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}

	offset = 0
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// ParsePaginationParams reads either (current,size) or legacy (limit,offset).
func ParsePaginationParams(c *gin.Context, defaultCurrent, defaultSize, maxSize int, defaultLimit, maxLimit int) (current, size, limit, offset int) {
	curRaw := strings.TrimSpace(c.Query("current"))
	sizeRaw := strings.TrimSpace(c.Query("size"))
	if curRaw != "" && sizeRaw != "" {
		cur, err1 := strconv.Atoi(curRaw)
		sz, err2 := strconv.Atoi(sizeRaw)
		if err1 == nil && err2 == nil && cur > 0 && sz > 0 {
			if maxSize > 0 && sz > maxSize {
				sz = maxSize
			}
			current = cur
			size = sz
			limit = sz
			offset = (current - 1) * size
			return
		}
	}

	limit, offset = ParseLimitOffset(c, defaultLimit, maxLimit)
	if limit <= 0 {
		limit = defaultLimit
	}
	if offset < 0 {
		offset = 0
	}
	size = limit
	current = offset/limit + 1
	return
}

// ParseCursor reads `cursor` and `limit` from query params.
func ParseCursor(c *gin.Context, defaultLimit, maxLimit int) (cursor string, limit int) {
	cursor = strings.TrimSpace(c.Query("cursor"))
	limit = defaultLimit
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	return cursor, limit
}
