package httpx

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/platform/errors"
)

// ApiResponse is the standard JSON envelope for all API responses.
type ApiResponse struct {
	Success bool                   `json:"success"`
	Code    string                 `json:"code"`
	Params  map[string]interface{} `json:"params,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
}

// Success writes a success JSON response.
func Success(c *gin.Context, status int, code string, data interface{}, params map[string]interface{}) {
	if code == "" {
		code = errors.CodeSuccess
	}
	c.JSON(status, ApiResponse{
		Success: true,
		Code:    code,
		Params:  params,
		Data:    data,
	})
}

// FailCode returns an error response with stable code for client i18n.
func FailCode(c *gin.Context, status int, code string, params map[string]interface{}) {
	if code == "" {
		code = errors.CodeUnknownError
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

// BuildParams constructs a params map from positional arguments.
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

// FailNotFound responds with 404 and the standard not-found code.
func FailNotFound(c *gin.Context) {
	FailCode(c, http.StatusNotFound, errors.CodeNotFound, nil)
}

// StatusToErrorCode maps HTTP status into stable code strings.
func StatusToErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return errors.CodeBadRequest
	case http.StatusUnauthorized:
		return errors.CodeUnauthorized
	case http.StatusForbidden:
		return errors.CodeForbidden
	case http.StatusNotFound:
		return errors.CodeNotFound
	case http.StatusConflict:
		return errors.CodeConflict
	case http.StatusTooManyRequests:
		return errors.CodeRateLimited
	case http.StatusInternalServerError:
		return errors.CodeInternal
	default:
		if status >= 400 && status < 500 {
			return errors.CodeBadRequest
		}
		if status >= 500 {
			return errors.CodeInternal
		}
		return errors.CodeUnknownError
	}
}

// FailStatus behaves like FailCode and attaches a stable code derived from HTTP status.
func FailStatus(c *gin.Context, status int, params map[string]interface{}) {
	code := StatusToErrorCode(status)
	FailCode(c, status, code, params)
}

// OK returns a 200 success response.
func OK(c *gin.Context, data interface{}) {
	Success(c, http.StatusOK, errors.CodeSuccess, data, nil)
}

// Created returns a 201 success response.
func Created(c *gin.Context, data interface{}) {
	Success(c, http.StatusCreated, errors.CodeCreated, data, nil)
}

// WriteError writes a mapped error response, or a fallback code when no mapper matches.
// Returns true when a response was written.
func WriteError(c *gin.Context, err error, fallbackCode string, fallbackStatus int, mappers ...errors.ErrorMapper) bool {
	return errors.WriteError(
		func(status int, code string, params map[string]interface{}) {
			FailCode(c, status, code, params)
		},
		err, fallbackCode, fallbackStatus, mappers...,
	)
}
