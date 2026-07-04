package pagination

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLimitOffset(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		defaultLimit int
		maxLimit     int
		wantLimit    int
		wantOffset   int
	}{
		{"defaults", "", 20, 100, 20, 0},
		{"custom limit", "?limit=50", 20, 100, 50, 0},
		{"custom offset", "?offset=10", 20, 100, 20, 10},
		{"both", "?limit=10&offset=5", 20, 100, 10, 5},
		{"exceeds max", "?limit=500", 20, 100, 100, 0},
		{"zero limit ignored", "?limit=0", 20, 100, 20, 0},
		{"negative offset ignored", "?offset=-5", 20, 100, 20, 0},
		{"no max limit", "?limit=999", 20, 0, 999, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)
			limit, offset := ParseLimitOffset(r, tt.defaultLimit, tt.maxLimit)
			assert.Equal(t, tt.wantLimit, limit)
			assert.Equal(t, tt.wantOffset, offset)
		})
	}
}

func TestParsePaginationParams(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		wantCurrent int
		wantSize    int
		wantLimit   int
		wantOffset  int
	}{
		{"current+size", "?current=3&size=10", 3, 10, 10, 20},
		{"limit+offset", "?limit=20&offset=40", 3, 20, 20, 40},
		{"defaults", "", 1, 20, 20, 0},
		{"current+size max", "?current=1&size=500", 1, 100, 100, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)
			current, size, limit, offset := ParsePaginationParams(r, 1, 20, 100, 20, 100)
			assert.Equal(t, tt.wantCurrent, current)
			assert.Equal(t, tt.wantSize, size)
			assert.Equal(t, tt.wantLimit, limit)
			assert.Equal(t, tt.wantOffset, offset)
		})
	}
}

func TestParseCursor(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		defaultLimit int
		maxLimit     int
		wantCursor   string
		wantLimit    int
	}{
		{"defaults", "", 20, 100, "", 20},
		{"with cursor", "?cursor=abc123", 20, 100, "abc123", 20},
		{"with limit", "?limit=50", 20, 100, "", 50},
		{"both", "?cursor=xyz&limit=10", 20, 100, "xyz", 10},
		{"exceeds max", "?limit=500", 20, 100, "", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)
			cursor, limit := ParseCursor(r, tt.defaultLimit, tt.maxLimit)
			assert.Equal(t, tt.wantCursor, cursor)
			assert.Equal(t, tt.wantLimit, limit)
		})
	}
}
