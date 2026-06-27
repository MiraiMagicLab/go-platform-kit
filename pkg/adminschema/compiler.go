// Package adminschema provides types and utilities for parsing and compiling
// admin panel contracts into runtime Shell configurations.
package adminschema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Section represents an admin panel section.
type Section struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Description  string            `json:"description,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	Config       interface{}       `json:"config,omitempty"`
}

// Targeting defines the primary target for the admin shell.
type Targeting struct {
	PrimaryTarget string `json:"primaryTarget"`
}

// Shell is the compiled admin panel configuration.
type Shell struct {
	Enabled           bool            `json:"enabled"`
	Sections          []Section       `json:"sections"`
	AdminCapabilities []string        `json:"adminCapabilities,omitempty"`
	AdminSections     []string        `json:"adminSections,omitempty"`
	FeatureFlags      map[string]bool `json:"featureFlags,omitempty"`
	Targeting         *Targeting      `json:"targeting,omitempty"`
	SchemaVersion     string          `json:"schemaVersion,omitempty"`
	ContractHash      string          `json:"contractHash,omitempty"`
}

// ContractSection is a raw contract section before normalization.
type ContractSection struct {
	ID           string                 `json:"id"`
	Title        string                 `json:"title,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Capabilities map[string]string      `json:"capabilities,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// Contract is a parsed admin contract.
type Contract struct {
	Version       string            `json:"version,omitempty"`
	SchemaVersion string            `json:"schemaVersion,omitempty"`
	Sections      []json.RawMessage `json:"sections,omitempty"`
	FeatureFlags  map[string]bool   `json:"featureFlags,omitempty"`
	Targeting     *Targeting        `json:"targeting,omitempty"`
}

// ParseContractSection tries to unmarshal a raw JSON section as either a plain string
// (section ID) or a full ContractSection struct.
func ParseContractSection(raw json.RawMessage) (ContractSection, bool) {
	var sectionID string
	if err := json.Unmarshal(raw, &sectionID); err == nil {
		return ContractSection{ID: sectionID}, true
	}

	var section ContractSection
	if err := json.Unmarshal(raw, &section); err != nil {
		return ContractSection{}, false
	}
	if strings.TrimSpace(section.ID) == "" {
		return ContractSection{}, false
	}
	return section, true
}

// BuildShellFromContract takes raw contract JSON and builds a complete Shell.
func BuildShellFromContract(contractRaw json.RawMessage) Shell {
	shell := Shell{
		Enabled:           false,
		Sections:          []Section{},
		AdminCapabilities: []string{},
		AdminSections:     []string{},
		SchemaVersion:     "v3",
	}
	if len(contractRaw) > 0 {
		sum := sha256.Sum256(contractRaw)
		shell.ContractHash = "sha256:" + hex.EncodeToString(sum[:])
	}
	admin := LoadContractAdmin(contractRaw)
	if admin == nil {
		return shell
	}
	shell.FeatureFlags = admin.FeatureFlags
	shell.Targeting = admin.Targeting
	shell.Sections = admin.Sections
	shell.AdminSections = make([]string, 0, len(admin.Sections))
	for _, section := range admin.Sections {
		shell.AdminSections = append(shell.AdminSections, section.ID)
	}
	shell.AdminCapabilities = append([]string{}, shell.AdminSections...)
	shell.Enabled = len(shell.Sections) > 0
	if strings.TrimSpace(admin.SchemaVersion) != "" {
		shell.SchemaVersion = admin.SchemaVersion
	}
	return shell
}

// LoadContractAdmin parses the contract JSON and extracts the admin section.
func LoadContractAdmin(contractRaw json.RawMessage) *Shell {
	if len(contractRaw) == 0 {
		return nil
	}
	var payload struct {
		Admin *Contract `json:"admin"`
	}
	if err := json.Unmarshal(contractRaw, &payload); err != nil || payload.Admin == nil {
		return nil
	}

	normalized := make([]Section, 0, len(payload.Admin.Sections))
	seen := map[string]bool{}
	for _, item := range payload.Admin.Sections {
		parsed, ok := ParseContractSection(item)
		if !ok {
			continue
		}
		section, ok := normalizeContractSection(parsed)
		if !ok || section.ID == "" || seen[section.ID] {
			continue
		}
		seen[section.ID] = true
		normalized = append(normalized, section)
	}
	return &Shell{
		Sections:      normalized,
		FeatureFlags:  payload.Admin.FeatureFlags,
		Targeting:     payload.Admin.Targeting,
		SchemaVersion: strings.TrimSpace(payload.Admin.SchemaVersion),
	}
}

func canonicalSectionID(id string) string {
	v := strings.TrimSpace(strings.ToLower(id))
	switch v {
	case "cron":
		return "cron-admin"
	default:
		return v
	}
}

func defaultSectionDefinition(id string) Section {
	switch canonicalSectionID(id) {
	case "overview":
		return Section{ID: "overview", Title: "App Overview", Description: "App-level introspection for the managed backend."}
	case "notifications":
		return Section{
			ID:           "notifications",
			Title:        "Notifications",
			Description:  "Inspect user inbox notifications and device tokens.",
			Capabilities: map[string]string{"read": "notifications:read", "write": "notifications:write"},
		}
	case "billing":
		return Section{
			ID:           "billing",
			Title:        "Billing",
			Description:  "Inspect and manage user entitlements.",
			Capabilities: map[string]string{"read": "billing:read", "write": "billing:write"},
		}
	case "cron-admin":
		return Section{
			ID:           "cron-admin",
			Title:        "Cron Admin",
			Description:  "Manage downstream cron jobs through the generic shell.",
			Capabilities: map[string]string{"read": "cron:read", "write": "cron:write", "run": "cron:run"},
		}
	case "cron-events":
		return Section{
			ID:           "cron-events",
			Title:        "Cron Events",
			Description:  "Recent downstream cron execution events.",
			Capabilities: map[string]string{"read": "cron:read"},
		}
	default:
		v := canonicalSectionID(id)
		return Section{ID: v, Title: v}
	}
}

func normalizeContractSection(raw ContractSection) (Section, bool) {
	id := canonicalSectionID(raw.ID)
	if id == "" {
		return Section{}, false
	}
	section := defaultSectionDefinition(id)
	if title := strings.TrimSpace(raw.Title); title != "" {
		section.Title = title
	}
	if description := strings.TrimSpace(raw.Description); description != "" {
		section.Description = description
	}
	if len(raw.Capabilities) > 0 {
		section.Capabilities = raw.Capabilities
	}
	if raw.Config != nil {
		section.Config = raw.Config
	}
	return section, true
}
