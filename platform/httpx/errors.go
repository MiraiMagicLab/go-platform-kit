package httpx

import (
	"github.com/gin-gonic/gin"
)

// MappedError describes a stable API error response derived from a domain error.
type MappedError struct {
	Status int
	Code   string
	Params map[string]any
}

// ErrorMapper translates a service-layer error into a [MappedError] when recognized.
type ErrorMapper func(err error) (MappedError, bool)

// MapError runs mappers in order and returns the first match.
func MapError(err error, mappers ...ErrorMapper) (MappedError, bool) {
	if err == nil {
		return MappedError{}, false
	}
	for _, mapFn := range mappers {
		if mapFn == nil {
			continue
		}
		if mapped, ok := mapFn(err); ok {
			return mapped, true
		}
	}
	return MappedError{}, false
}

// WriteError writes a mapped error response, or a fallback code when no mapper matches.
// Returns true when a response was written.
func WriteError(c *gin.Context, err error, fallbackCode string, fallbackStatus int, mappers ...ErrorMapper) bool {
	if mapped, ok := MapError(err, mappers...); ok {
		FailCode(c, mapped.Status, mapped.Code, mapped.Params)
		return true
	}
	if fallbackCode != "" {
		FailCode(c, fallbackStatus, fallbackCode, nil)
		return true
	}
	return false
}
