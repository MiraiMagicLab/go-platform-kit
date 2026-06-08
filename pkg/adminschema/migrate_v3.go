package adminschema

import (
	"encoding/json"
	"strings"
)

// MapLegacyPermissionToCapability converts admin.* permission strings to App Capability notation.
// Example: "admin.notifications.read" -> "notifications:read"
func MapLegacyPermissionToCapability(perm string) (string, bool) {
	perm = strings.TrimSpace(perm)
	const prefix = "admin."
	if !strings.HasPrefix(perm, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(perm, prefix)
	i := strings.LastIndex(rest, ".")
	if i <= 0 {
		return "", false
	}
	return rest[:i] + ":" + rest[i+1:], true
}

func migrateCapabilityMap(m map[string]string) (map[string]string, bool) {
	if len(m) == 0 {
		return nil, false
	}
	out := make(map[string]string, len(m))
	changed := false
	for k, v := range m {
		if cap, ok := MapLegacyPermissionToCapability(v); ok {
			out[k] = cap
			changed = true
			continue
		}
		out[k] = v
	}
	return out, changed
}

// MigrateSchemaContentV3 rewrites admin section permissions -> capabilities and bumps schemaVersion to v3.
func MigrateSchemaContentV3(raw json.RawMessage) (json.RawMessage, bool, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return raw, false, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return raw, false, err
	}
	adminRaw, ok := root["admin"]
	if !ok {
		return raw, false, nil
	}
	var admin map[string]interface{}
	if err := json.Unmarshal(adminRaw, &admin); err != nil {
		return raw, false, err
	}
	changed := false
	if sv, ok := admin["schemaVersion"].(string); ok && sv != "" && sv != "v3" {
		admin["schemaVersion"] = "v3"
		changed = true
	} else if admin["schemaVersion"] == nil || admin["schemaVersion"] == "" {
		admin["schemaVersion"] = "v3"
		changed = true
	}
	sections, ok := admin["sections"].([]interface{})
	if !ok {
		if !changed {
			return raw, false, nil
		}
		return marshalRoot(root, admin)
	}
	for i, sec := range sections {
		sm, ok := sec.(map[string]interface{})
		if !ok {
			continue
		}
		if perms, ok := sm["permissions"].(map[string]interface{}); ok && len(perms) > 0 {
			in := map[string]string{}
			for k, v := range perms {
				if s, ok := v.(string); ok {
					in[k] = s
				}
			}
			if caps, migrated := migrateCapabilityMap(in); migrated {
				sm["capabilities"] = toIfaceMap(caps)
				delete(sm, "permissions")
				changed = true
			}
		}
		if caps, ok := sm["capabilities"].(map[string]interface{}); ok {
			in := map[string]string{}
			for k, v := range caps {
				if s, ok := v.(string); ok {
					in[k] = s
				}
			}
			if out, migrated := migrateCapabilityMap(in); migrated {
				sm["capabilities"] = toIfaceMap(out)
				changed = true
			}
		}
		sections[i] = sm
	}
	admin["sections"] = sections
	if !changed {
		return raw, false, nil
	}
	return marshalRoot(root, admin)
}

func toIfaceMap(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func marshalRoot(root map[string]json.RawMessage, admin map[string]interface{}) (json.RawMessage, bool, error) {
	b, err := json.Marshal(admin)
	if err != nil {
		return nil, false, err
	}
	root["admin"] = b
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}
