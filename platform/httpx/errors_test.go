package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

func TestMapError(t *testing.T) {
	mapper := func(err error) (httpx.MappedError, bool) {
		if errors.Is(err, errors.New("known")) {
			return httpx.MappedError{Status: http.StatusTeapot, Code: "M0000999"}, true
		}
		return httpx.MappedError{}, false
	}

	_, ok := httpx.MapError(errors.New("other"), mapper)
	assert.False(t, ok)

	mapped, ok := httpx.MapError(errors.New("known"), func(err error) (httpx.MappedError, bool) {
		if err.Error() == "known" {
			return httpx.MappedError{Status: http.StatusBadRequest, Code: httpx.CodeBadRequest}, true
		}
		return httpx.MappedError{}, false
	})
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, mapped.Status)
}

func TestWriteError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	written := httpx.WriteError(c, errors.New("x"), httpx.CodeInternal, http.StatusInternalServerError)
	assert.True(t, written)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
