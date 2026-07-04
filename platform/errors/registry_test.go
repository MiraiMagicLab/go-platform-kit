package errors_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
)

func TestRenderMessage(t *testing.T) {
	got := apperrors.RenderMessage("Hello {0}, you have {1} new messages in your {2} bucket.", "Alice", 5, "inbox")
	want := "Hello Alice, you have 5 new messages in your inbox bucket."
	assert.Equal(t, want, got)
}

func TestRegisterMessages(t *testing.T) {
	before := apperrors.AllRegisteredCodes()

	apperrors.RegisterMessages(map[string]string{
		"TEST001": "Test message one",
		"TEST002": "Test message two",
		"":        "empty key ignored",
		"TEST003": "",
	})

	after := apperrors.AllRegisteredCodes()
	assert.Equal(t, "Test message one", after["TEST001"])
	assert.Equal(t, "Test message two", after["TEST002"])
	assert.Equal(t, len(before)+2, len(after))
}

func TestDefaultMessage(t *testing.T) {
	msg := apperrors.DefaultMessage(apperrors.CodeBadRequest)
	assert.Equal(t, "Invalid request", msg)

	msg = apperrors.DefaultMessage("NONEXISTENT")
	assert.Equal(t, "", msg)
}

func TestDefaultMessageCommonCodes(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{apperrors.CodeSuccess, "Success"},
		{apperrors.CodeNotFound, "Resource not found"},
		{apperrors.CodeInternal, "Internal server error"},
		{apperrors.CodeAuthInvalidCredentials, "Invalid credentials"},
		{apperrors.CodeAuthTokenExpired, "Token expired"},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			assert.Equal(t, tt.want, apperrors.DefaultMessage(tt.code))
		})
	}
}
