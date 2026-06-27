package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
)

// Option configures the auth [Module] during construction.
type Option func(*options) error

type options struct {
	cfg         Config
	pg          *pgxpool.Pool
	redis       *goredis.Client
	jwt         *JWTManager
	logger      log.Logger
	store       *Store
	permCache   StringSliceCache
	denylist    AccessTokenDenylist
	emailSender EmailSender
}

// WithConfig sets the auth domain configuration.
func WithConfig(cfg Config) Option {
	return func(o *options) error {
		o.cfg = cfg
		return nil
	}
}

// WithPostgres provides a shared PostgreSQL pool opened via [platform/postgres].
func WithPostgres(pg *pgxpool.Pool) Option {
	return func(o *options) error {
		o.pg = pg
		return nil
	}
}

// WithRedis provides an optional Redis client for permission cache and token denylist.
func WithRedis(rdb *goredis.Client) Option {
	return func(o *options) error {
		o.redis = rdb
		return nil
	}
}

// WithJWT overrides the default JWT manager constructed from config secrets.
func WithJWT(jwt *JWTManager) Option {
	return func(o *options) error {
		o.jwt = jwt
		return nil
	}
}

// WithLogger injects a platform logger. Defaults to [log.Noop].
func WithLogger(logger log.Logger) Option {
	return func(o *options) error {
		o.logger = logger
		return nil
	}
}

// WithStore replaces the default PostgreSQL-backed [Store] (useful for tests).
func WithStore(store Store) Option {
	return func(o *options) error {
		o.store = &store
		return nil
	}
}

// WithPermCache overrides the RBAC permission cache (defaults to [NoopStringSliceCache]).
func WithPermCache(cache StringSliceCache) Option {
	return func(o *options) error {
		o.permCache = cache
		return nil
	}
}

// WithDenylist overrides the access-token denylist (defaults to [NoopAccessTokenDenylist]).
func WithDenylist(denylist AccessTokenDenylist) Option {
	return func(o *options) error {
		o.denylist = denylist
		return nil
	}
}

// WithEmailSender injects a shared [platform/mail.Mailer] for verify/reset emails.
func WithEmailSender(sender EmailSender) Option {
	return func(o *options) error {
		o.emailSender = sender
		return nil
	}
}
