package httpx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

func TestMapError(t *testing.T) {
	mapper := func(err error) (apperrors.MappedError, bool) {
		if errors.Is(err, errors.New("known")) {
			return apperrors.MappedError{Status: http.StatusTeapot, Code: "M0000999"}, true
		}
		return apperrors.MappedError{}, false
	}

	_, ok := apperrors.MapError(errors.New("other"), mapper)
	assert.False(t, ok)

	mapped, ok := apperrors.MapError(errors.New("known"), func(err error) (apperrors.MappedError, bool) {
		if err.Error() == "known" {
			return apperrors.MappedError{Status: http.StatusBadRequest, Code: apperrors.CodeBadRequest}, true
		}
		return apperrors.MappedError{}, false
	})
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, mapped.Status)
}

func TestWriteError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	written := httpx.WriteError(c, errors.New("x"), apperrors.CodeInternal, http.StatusInternalServerError)
	assert.True(t, written)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
