package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_requiresURL(t *testing.T) {
	err := Config{}.Validate()
	require.Error(t, err)
}

func TestConfig_IsConfigured(t *testing.T) {
	require.False(t, Config{}.IsConfigured())
	require.True(t, Config{URL: "postgres://localhost/db"}.IsConfigured())
}
