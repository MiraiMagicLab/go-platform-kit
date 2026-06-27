package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen_requiresPostgres(t *testing.T) {
	_, err := Open(context.Background(), WithConfig(DefaultConfig()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres")
}

func TestDefaultConfig_validateRequiresSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWTAccessSecret = ""
	err := cfg.Validate()
	require.Error(t, err)
}

func TestMapError_invalidCredentials(t *testing.T) {
	mapped, ok := MapError(ErrInvalidCredentials)
	assert.True(t, ok)
	assert.Equal(t, 401, mapped.Status)
}
