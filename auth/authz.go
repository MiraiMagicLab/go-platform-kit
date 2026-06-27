package auth

import "fmt"

// AuthZMode selects authorization behavior for an embedded auth instance.
type AuthZMode string

const (
	AuthZNone AuthZMode = "none"
	AuthZRole AuthZMode = "role"
	AuthZRbac AuthZMode = "rbac"
)

// AuthZConfig configures authorization mode for the host application.
//
// Mode controls [Auth.RequireAccess] behavior:
//   - [AuthZNone]: no authorization check (pass-through)
//   - [AuthZRole]: values are role names ([Auth.RequireRole] semantics)
//   - [AuthZRbac]: values are permission names ([Auth.RequirePermission] semantics)
type AuthZConfig struct {
	Mode AuthZMode
}

func (c AuthZConfig) validate() error {
	switch c.Mode {
	case AuthZNone, AuthZRole, AuthZRbac:
		return nil
	case "":
		return fmt.Errorf("auth: AuthZ.Mode is required (none, role, or rbac)")
	default:
		return fmt.Errorf("auth: invalid AuthZ.Mode %q", c.Mode)
	}
}

func (c AuthZConfig) usesRBAC() bool {
	return c.Mode == AuthZRbac
}
