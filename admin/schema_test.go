package admin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapLegacyPermissionToCapability(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"admin.notifications.read", "notifications:read", true},
		{"admin.billing.write", "billing:write", true},
		{"admin.cron.run", "cron:run", true},
		{"user.read", "", false},
		{"", "", false},
		{"admin.", "", false},
		{"admin.single", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, ok := MapLegacyPermissionToCapability(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestMigrateV3(t *testing.T) {
	input := map[string]interface{}{
		"version": "1.0",
		"admin": map[string]interface{}{
			"schemaVersion": "v2.1",
			"sections": []interface{}{
				map[string]interface{}{
					"id":    "notifications",
					"title": "Notifications",
					"permissions": map[string]interface{}{
						"read":  "admin.notifications.read",
						"write": "admin.notifications.write",
					},
				},
			},
		},
	}

	raw, err := json.Marshal(input)
	require.NoError(t, err)

	result, changed, err := MigrateV3(raw)
	require.NoError(t, err)
	assert.True(t, changed)

	var output map[string]interface{}
	require.NoError(t, json.Unmarshal(result, &output))

	admin := output["admin"].(map[string]interface{})
	assert.Equal(t, "v3", admin["schemaVersion"])

	sections := admin["sections"].([]interface{})
	section := sections[0].(map[string]interface{})
	assert.Nil(t, section["permissions"])

	caps := section["capabilities"].(map[string]interface{})
	assert.Equal(t, "notifications:read", caps["read"])
	assert.Equal(t, "notifications:write", caps["write"])
}

func TestCompile(t *testing.T) {
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

	shell, err := Compile(raw)
	require.NoError(t, err)

	assert.True(t, shell.Enabled)
	assert.Len(t, shell.Sections, 2)
	assert.Equal(t, "overview", shell.Sections[0].ID)
	assert.Equal(t, "users", shell.Sections[1].ID)
	assert.Equal(t, "v3", shell.SchemaVersion)
	assert.NotEmpty(t, shell.ContractHash)
}

func TestCompile_Empty(t *testing.T) {
	shell, err := Compile(nil)
	require.NoError(t, err)
	assert.False(t, shell.Enabled)
	assert.Empty(t, shell.Sections)
	assert.Equal(t, "v3", shell.SchemaVersion)
}

func TestCompile_InvalidJSON(t *testing.T) {
	_, err := Compile([]byte("invalid json"))
	assert.Error(t, err)
}
