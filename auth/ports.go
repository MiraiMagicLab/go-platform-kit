// Repository and cache port types re-exported for host apps, fakes, and integration tests.
package auth

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
)

type (
	// ListUsersFilter defines filtering options for admin user listing.
	ListUsersFilter = ports.ListUsersFilter
	// UserRepository persists user accounts.
	UserRepository = ports.UserRepository
	// RefreshTokenRepository persists refresh tokens and rotation.
	RefreshTokenRepository = ports.RefreshTokenRepository
	// SessionRepository persists login sessions.
	SessionRepository = ports.SessionRepository
	// RBACRepository persists roles, permissions, and assignments.
	RBACRepository = ports.RBACRepository
	// MFARepository persists TOTP secrets and recovery codes.
	MFARepository = ports.MFARepository
	// IdentityRepository persists OAuth provider identities.
	IdentityRepository = ports.IdentityRepository
	// AuditRepository persists security audit events.
	AuditRepository = ports.AuditRepository
	// EmailTokenRepository persists verify/reset email tokens.
	EmailTokenRepository = ports.EmailTokenRepository
	// StringSliceCache caches permission lists (typically Redis-backed).
	StringSliceCache = ports.StringSliceCache
	// NoopStringSliceCache is a no-op [StringSliceCache] for single-node deployments.
	NoopStringSliceCache = ports.NoopStringSliceCache
	// AccessTokenDenylist tracks revoked access-token JTIs until expiry.
	AccessTokenDenylist = ports.AccessTokenDenylist
	// NoopAccessTokenDenylist is a no-op [AccessTokenDenylist].
	NoopAccessTokenDenylist = ports.NoopAccessTokenDenylist
	// Store bundles all repository interfaces for wiring.
	Store = ports.Store
)

// EmailSender delivers transactional emails via the shared platform mailer.
type EmailSender = mail.Mailer
