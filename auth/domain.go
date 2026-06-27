package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"

// Domain types re-exported for host apps and tests.
type (
	User             = domain.User
	Session          = domain.Session
	SessionListInfo  = domain.SessionListInfo
	ClientMeta       = domain.ClientMeta
	RefreshToken     = domain.RefreshToken
	RotateResult     = domain.RotateResult
	AccessTokenMeta  = domain.AccessTokenMeta
	Role             = domain.Role
	Permission       = domain.Permission
	MFAConfig        = domain.MFAConfig
	MFASetup         = domain.MFASetup
	OAuthIdentity    = domain.OAuthIdentity
	AuditEntry       = domain.AuditEntry
	EmailActionToken = domain.EmailActionToken
)

// Sentinel and typed errors returned by auth use cases.
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
