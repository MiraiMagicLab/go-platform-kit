package adminschema

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildShellFromContract(t *testing.T) {
	contract := map[string]interface{}{
		"admin": map[string]interface{}{
			"sections": []interface{}{
				"overview",
				map[string]interface{}{
					"id":    "users",
					"title": "User Management",
				},
			},
		},
	}

	raw, err := json.Marshal(contract)
	require.NoError(t, err)

	shell := BuildShellFromContract(raw)

	assert.True(t, shell.Enabled)
	assert.Len(t, shell.Sections, 2)
	assert.Equal(t, "overview", shell.Sections[0].ID)
	assert.Equal(t, "users", shell.Sections[1].ID)
	assert.Equal(t, "v3", shell.SchemaVersion)
	assert.NotEmpty(t, shell.ContractHash)
}

func TestBuildShellFromContract_Empty(t *testing.T) {
	shell := BuildShellFromContract(nil)

	assert.False(t, shell.Enabled)
	assert.Empty(t, shell.Sections)
	assert.Equal(t, "v3", shell.SchemaVersion)
}

func TestBuildShellFromContract_InvalidJSON(t *testing.T) {
	shell := BuildShellFromContract([]byte("invalid json"))

	assert.False(t, shell.Enabled)
	assert.Empty(t, shell.Sections)
}
