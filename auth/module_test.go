package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_requiresPostgres(t *testing.T) {
	_, err := New(context.Background(), WithConfig(DefaultConfig()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres")
}

func TestDefaultConfig_validateRequiresSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWTAccessSecret = ""
	err := cfg.Validate()
	require.Error(t, err)
}
