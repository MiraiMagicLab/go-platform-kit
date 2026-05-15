package authkit

import "fmt"

// AuthZMode selects authorization behavior for an embedded authkit instance.
type AuthZMode string

const (
	// AuthZNone enables authentication only (no role/permission seeding).
	AuthZNone AuthZMode = "none"
	// AuthZRole seeds roles for end-user checks; use RequireRole on app JWT routes.
	// Intended for platform app backends (lingo-engine, travel, etc.).
	AuthZRole AuthZMode = "role"
	// AuthZRbac seeds permissions and enables RequirePermission on control-plane.
	AuthZRbac AuthZMode = "rbac"
)

// AuthZConfig configures authorization mode for the host application.
// Mode MUST be set explicitly (no default).
type AuthZConfig struct {
	Mode AuthZMode
}

func (c AuthZConfig) validate() error {
	switch c.Mode {
	case AuthZNone, AuthZRole, AuthZRbac:
		return nil
	case "":
		return fmt.Errorf("authkit: AuthZ.Mode is required (none, role, or rbac)")
	default:
		return fmt.Errorf("authkit: invalid AuthZ.Mode %q", c.Mode)
	}
}

func (c AuthZConfig) usesRBAC() bool {
	return c.Mode == AuthZRbac
}
