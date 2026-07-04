package errors

// MappedError describes a stable API error response derived from a domain error.
type MappedError struct {
	Status int
	Code   string
	Params map[string]interface{}
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

// WriteErrorFn is a function that writes an error response with the given status, code, and params.
// This avoids a circular dependency with the httpx package.
type WriteErrorFn func(status int, code string, params map[string]interface{})

// WriteError runs the error mapper chain and calls writeFn with the result.
// If no mapper matches, it falls back to the provided fallback code and status.
// Returns true when a response was written.
func WriteError(writeFn WriteErrorFn, err error, fallbackCode string, fallbackStatus int, mappers ...ErrorMapper) bool {
	if mapped, ok := MapError(err, mappers...); ok {
		writeFn(mapped.Status, mapped.Code, mapped.Params)
		return true
	}
	if fallbackCode != "" {
		writeFn(fallbackStatus, fallbackCode, nil)
		return true
	}
	return false
}
