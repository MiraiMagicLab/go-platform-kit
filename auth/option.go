package auth

import (
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"
	oauthuc "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
)

// Option configures [Auth] during [Open].
type Option func(*options) error

type options struct {
	cfg         Config
	pg          *pgxpool.Pool
	redis       *goredis.Client
	jwt         *jwt.Manager
	logger      log.Logger
	store       *ports.Store
	permCache   ports.StringSliceCache
	denylist    ports.AccessTokenDenylist
	emailSender mail.Mailer
	oauthOpts     []oauthuc.Option
	oauthTokenURL string
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
func WithJWT(jwtm *jwt.Manager) Option {
	return func(o *options) error {
		o.jwt = jwtm
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

// WithStore replaces the default PostgreSQL-backed store (for tests; see [auth/testkit]).
func WithStore(store ports.Store) Option {
	return func(o *options) error {
		o.store = &store
		return nil
	}
}

// WithPermCache overrides the RBAC permission cache.
func WithPermCache(cache ports.StringSliceCache) Option {
	return func(o *options) error {
		o.permCache = cache
		return nil
	}
}

// WithDenylist overrides the access-token denylist.
func WithDenylist(denylist ports.AccessTokenDenylist) Option {
	return func(o *options) error {
		o.denylist = denylist
		return nil
	}
}

// WithEmailSender injects a shared [platform/mail.Mailer] for verify/reset emails.
func WithEmailSender(sender mail.Mailer) Option {
	return func(o *options) error {
		o.emailSender = sender
		return nil
	}
}

// WithOAuthOptions passes options to the Google OAuth service (for tests or custom HTTP client).
func WithOAuthOptions(opts ...oauthuc.Option) Option {
	return func(o *options) error {
		o.oauthOpts = append(o.oauthOpts, opts...)
		return nil
	}
}

// WithGoogleOAuthTokenURL overrides the Google token endpoint (integration tests only).
func WithGoogleOAuthTokenURL(url string) Option {
	return func(o *options) error {
		o.oauthTokenURL = url
		return nil
	}
}
