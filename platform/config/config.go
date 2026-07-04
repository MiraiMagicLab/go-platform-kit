package config

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
	"github.com/MiraiMagicLab/go-platform-kit/platform/storage"
)

// AppConfig holds application-level metadata loaded from the environment.
type AppConfig struct {
	Name string
	Port string
	Env  string
}

// Infra groups shared infrastructure settings opened once per application.
type Infra struct {
	Postgres postgres.Config
	Redis    redis.Config
	Storage  storage.Config
	Mail     mail.Config
}

// Config is the top-level infrastructure configuration for a backend app.
type Config struct {
	App   AppConfig
	Infra Infra
}

// Validate checks configured infrastructure sections.
func (c Config) Validate() error {
	if c.Infra.Postgres.IsConfigured() {
		if err := c.Infra.Postgres.Validate(); err != nil {
			return err
		}
	}
	if c.Infra.Redis.IsConfigured() {
		if err := c.Infra.Redis.Validate(); err != nil {
			return err
		}
	}
	if c.Infra.Storage.IsConfigured() {
		if err := c.Infra.Storage.Validate(); err != nil {
			return err
		}
	}
	if c.Infra.Mail.IsConfigured() {
		if err := c.Infra.Mail.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// FromEnv loads infrastructure settings from standard environment variables.
func FromEnv() Config {
	redisCfg := redis.Config{
		URL:      os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"),
	}
	if redisCfg.URL == "" {
		redisCfg.Addr = envOr("REDIS_ADDR", "localhost:6379")
	}
	if db := strings.TrimSpace(os.Getenv("REDIS_DB")); db != "" {
		if n, err := strconv.Atoi(db); err == nil {
			redisCfg.DB = n
		}
	}

	storageCfg := storage.Config{
		AccountID:  strings.TrimSpace(os.Getenv("R2_ACCOUNT_ID")),
		Bucket:     firstNonEmpty(os.Getenv("R2_BUCKET"), os.Getenv("STORAGE_BUCKET")),
		AccessKey:  strings.TrimSpace(os.Getenv("R2_ACCESS_KEY")),
		SecretKey:  strings.TrimSpace(os.Getenv("R2_SECRET_KEY")),
		PublicBase: firstNonEmpty(os.Getenv("R2_PUBLIC_BASE"), os.Getenv("STORAGE_PUBLIC_BASE")),
		Endpoint:   strings.TrimSpace(os.Getenv("R2_ENDPOINT")),
	}

	return Config{
		App: AppConfig{
			Name: envOr("APP_NAME", "app"),
			Port: envOr("PORT", "8080"),
			Env:  envOr("APP_ENV", "development"),
		},
		Infra: Infra{
			Postgres: postgres.Config{URL: os.Getenv("DATABASE_URL")},
			Redis:    redisCfg,
			Storage:  storageCfg,
			Mail: mail.Config{
				Host: os.Getenv("SMTP_HOST"),
				Port: ParseSMTPPort(587),
				User: os.Getenv("SMTP_USER"),
				Pass: os.Getenv("SMTP_PASS"),
				From: os.Getenv("SMTP_FROM"),
			},
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

// ErrNotConfigured indicates optional infrastructure was requested but not set.
var ErrNotConfigured = errors.New("config: not configured")

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
