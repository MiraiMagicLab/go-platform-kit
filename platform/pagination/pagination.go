package pagination

import (
	"net/http"
	"strconv"
	"strings"
)

// Meta describes common limit/offset pagination metadata.
type Meta struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

// Result wraps records with limit/offset pagination metadata.
type Result struct {
	Records    interface{} `json:"records"`
	Pagination Meta        `json:"pagination"`
}

// CursorMeta describes cursor-based pagination metadata.
type CursorMeta struct {
	NextCursor string `json:"nextCursor" example:"opaque_string"`
	HasMore    bool   `json:"hasMore"`
}

// CursorResult wraps records with cursor-based pagination metadata.
type CursorResult struct {
	Records    interface{} `json:"records"`
	Pagination CursorMeta  `json:"pagination"`
}

// QueryRecord is the pagination format: {records, current, size, total}.
type QueryRecord struct {
	Records interface{} `json:"records"`
	Current int         `json:"current"`
	Size    int         `json:"size"`
	Total   int         `json:"total"`
}

// ParseLimitOffset reads `limit` + `offset` from query params and applies sane bounds.
func ParseLimitOffset(r *http.Request, defaultLimit, maxLimit int) (limit, offset int) {
	limit = defaultLimit
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}

	offset = 0
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// ParsePaginationParams reads either (current,size) or legacy (limit,offset) from query params.
func ParsePaginationParams(r *http.Request, defaultCurrent, defaultSize, maxSize int, defaultLimit, maxLimit int) (current, size, limit, offset int) {
	curRaw := strings.TrimSpace(r.URL.Query().Get("current"))
	sizeRaw := strings.TrimSpace(r.URL.Query().Get("size"))
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

	limit, offset = ParseLimitOffset(r, defaultLimit, maxLimit)
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
func ParseCursor(r *http.Request, defaultLimit, maxLimit int) (cursor string, limit int) {
	cursor = strings.TrimSpace(r.URL.Query().Get("cursor"))
	limit = defaultLimit
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	return cursor, limit
}
