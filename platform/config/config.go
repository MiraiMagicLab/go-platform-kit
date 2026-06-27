package config

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
	"github.com/MiraiMagicLab/go-platform-kit/platform/storage"
)

// Infra groups shared infrastructure settings opened once per application.
type Infra struct {
	Postgres postgres.Config
	Redis    redis.Config
	Storage  storage.Config
}

// Auth holds cross-cutting auth secrets commonly loaded from environment.
type Auth struct {
	JWTAccessSecret      string
	JWTRefreshSecret     string
	DataEncryptionKeyB64 string
}

// Config is the top-level infrastructure configuration for a backend app.
type Config struct {
	Infra Infra
	Auth  Auth
}

// Validate checks required infrastructure fields.
func (c Config) Validate() error {
	if c.Infra.Postgres.IsConfigured() {
		if err := c.Infra.Postgres.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// FromEnv loads infrastructure settings from standard environment variables.
func FromEnv() Config {
	return Config{
		Infra: Infra{
			Postgres: postgres.Config{URL: os.Getenv("DATABASE_URL")},
			Redis: redis.Config{
				URL:  os.Getenv("REDIS_URL"),
				Addr: envOr("REDIS_ADDR", "localhost:6379"),
			},
			Storage: storage.Config{
				Provider:   os.Getenv("STORAGE_PROVIDER"),
				Bucket:     os.Getenv("STORAGE_BUCKET"),
				AccountID:  os.Getenv("R2_ACCOUNT_ID"),
				AccessKey:  os.Getenv("R2_ACCESS_KEY"),
				SecretKey:  os.Getenv("R2_SECRET_KEY"),
				PublicBase: os.Getenv("STORAGE_PUBLIC_BASE"),
			},
		},
		Auth: Auth{
			JWTAccessSecret:      os.Getenv("JWT_ACCESS_SECRET"),
			JWTRefreshSecret:     os.Getenv("JWT_REFRESH_SECRET"),
			DataEncryptionKeyB64: os.Getenv("DATA_ENCRYPTION_KEY_B64"),
		},
	}
}

// Load validates cfg and returns it or an error.
func Load(cfg Config) (Config, error) {
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// ParseSMTPPort reads SMTP_PORT with a default fallback.
func ParseSMTPPort(def int) int {
	raw := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ErrNotConfigured indicates optional infrastructure was requested but not set.
var ErrNotConfigured = errors.New("config: not configured")
