package errors_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
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
	var writtenStatus int
	var writtenCode string
	writeFn := func(status int, code string, params map[string]interface{}) {
		writtenStatus = status
		writtenCode = code
	}

	written := apperrors.WriteError(writeFn, errors.New("x"), apperrors.CodeInternal, http.StatusInternalServerError)
	assert.True(t, written)
	assert.Equal(t, http.StatusInternalServerError, writtenStatus)
	assert.Equal(t, apperrors.CodeInternal, writtenCode)
}

func TestWriteErrorWithMapper(t *testing.T) {
	var writtenStatus int
	var writtenCode string
	writeFn := func(status int, code string, params map[string]interface{}) {
		writtenStatus = status
		writtenCode = code
	}

	mapper := func(err error) (apperrors.MappedError, bool) {
		if err.Error() == "known" {
			return apperrors.MappedError{Status: http.StatusTeapot, Code: "CUSTOM"}, true
		}
		return apperrors.MappedError{}, false
	}

	written := apperrors.WriteError(writeFn, errors.New("known"), apperrors.CodeInternal, http.StatusInternalServerError, mapper)
	assert.True(t, written)
	assert.Equal(t, http.StatusTeapot, writtenStatus)
	assert.Equal(t, "CUSTOM", writtenCode)
}

func TestWriteErrorNoFallback(t *testing.T) {
	writeFn := func(status int, code string, params map[string]interface{}) {
		t.Fatal("writeFn should not be called")
	}

	written := apperrors.WriteError(writeFn, errors.New("x"), "", 0)
	assert.False(t, written)
}
