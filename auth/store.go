package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"

type (
	ListUsersFilter         = store.ListUsersFilter
	UserRepository          = store.UserRepository
	RefreshTokenRepository  = store.RefreshTokenRepository
	SessionRepository       = store.SessionRepository
	RBACRepository          = store.RBACRepository
	MFARepository           = store.MFARepository
	IdentityRepository      = store.IdentityRepository
	AuditRepository         = store.AuditRepository
	EmailTokenRepository    = store.EmailTokenRepository
	StringSliceCache        = store.StringSliceCache
	NoopStringSliceCache    = store.NoopStringSliceCache
	AccessTokenDenylist     = store.AccessTokenDenylist
	NoopAccessTokenDenylist = store.NoopAccessTokenDenylist
	EmailSender             = store.EmailSender
	Store                   = store.Store
)
