// Package testkit provides test doubles for auth integration tests.
package testkit

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

type (
	Store                   = ports.Store
	UserRepository          = ports.UserRepository
	RefreshTokenRepository  = ports.RefreshTokenRepository
	SessionRepository       = ports.SessionRepository
	RBACRepository          = ports.RBACRepository
	MFARepository           = ports.MFARepository
	IdentityRepository      = ports.IdentityRepository
	AuditRepository         = ports.AuditRepository
	EmailTokenRepository    = ports.EmailTokenRepository
	StringSliceCache        = ports.StringSliceCache
	NoopStringSliceCache    = ports.NoopStringSliceCache
	AccessTokenDenylist     = ports.AccessTokenDenylist
	NoopAccessTokenDenylist = ports.NoopAccessTokenDenylist
)
