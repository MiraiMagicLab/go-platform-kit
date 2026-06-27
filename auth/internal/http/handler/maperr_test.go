package handler

import (
	"testing"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestMapAuthError(t *testing.T) {
	mapped, ok := MapAuthError(domain.ErrInvalidCredentials)
	assert.True(t, ok)
	assert.Equal(t, 401, mapped.Status)

	_, ok = MapAuthError(domain.ErrAccountLocked{})
	assert.True(t, ok)

	_, ok = MapAuthError(assert.AnError)
	assert.False(t, ok)
}
