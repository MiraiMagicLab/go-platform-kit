package auth

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

// DTOs returned by headless use-case methods.
type (
	ClientMeta      = domain.ClientMeta
	Session         = domain.Session
	User            = domain.User
	MFASetup        = domain.MFASetup
	ListUsersFilter = ports.ListUsersFilter
)

// UserProfile is the authenticated user with role and permission names.
type UserProfile struct {
	User        User     `json:"user"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type OAuthProvider string

const OAuthGoogle OAuthProvider = "google"

// Sentinel and typed errors returned by use cases.
var (
	ErrInvalidCredentials = domain.ErrInvalidCredentials
	ErrInvalidRefresh     = domain.ErrInvalidRefresh
	ErrSessionNotFound    = domain.ErrSessionNotFound
)

type (
	ErrAccountLocked    = domain.ErrAccountLocked
	ErrUserBanned       = domain.ErrUserBanned
	ErrEmailNotVerified = domain.ErrEmailNotVerified
	ErrMFARequired      = domain.ErrMFARequired
)
