package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/MiraiMagicLab/go-platform-kit/platform/errors"
)

func TestSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Success(c, http.StatusOK, errors.CodeSuccess, gin.H{"key": "value"}, nil)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestFailCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	FailCode(c, http.StatusBadRequest, errors.CodeBadRequest, nil)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestStatusToErrorCode(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, errors.CodeBadRequest},
		{http.StatusUnauthorized, errors.CodeUnauthorized},
		{http.StatusForbidden, errors.CodeForbidden},
		{http.StatusNotFound, errors.CodeNotFound},
		{http.StatusConflict, errors.CodeConflict},
		{http.StatusTooManyRequests, errors.CodeRateLimited},
		{http.StatusInternalServerError, errors.CodeInternal},
		{418, errors.CodeBadRequest},
		{502, errors.CodeInternal},
		{200, errors.CodeUnknownError},
	}
	for _, tt := range tests {
		got := StatusToErrorCode(tt.status)
		if got != tt.want {
			t.Errorf("StatusToErrorCode(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
