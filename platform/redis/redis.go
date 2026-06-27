package redis

import (
	"context"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
)

// Config describes Redis connection settings.
type Config struct {
	URL      string
	Addr     string
	Password string
	DB       int
}

// IsConfigured reports whether Redis settings are present.
func (c Config) IsConfigured() bool {
	return c.URL != "" || c.Addr != ""
}

// Validate checks required fields when Redis is configured.
func (c Config) Validate() error {
	if !c.IsConfigured() {
		return errors.New("redis: not configured")
	}
	return nil
}

// Open creates a Redis client from cfg and verifies connectivity with Ping.
func Open(ctx context.Context, cfg Config) (*goredis.Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var opts *goredis.Options
	if cfg.URL != "" {
		parsed, err := goredis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("redis: parse URL: %w", err)
		}
		opts = parsed
	} else {
		opts = &goredis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
		}
	}
	client := goredis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return client, nil
}

// Ping verifies the client can reach Redis.
func Ping(ctx context.Context, client *goredis.Client) error {
	if client == nil {
		return errors.New("redis: client is nil")
	}
	return client.Ping(ctx).Err()
}

// Close closes the Redis client.
func Close(client *goredis.Client) error {
	if client == nil {
		return nil
	}
	return client.Close()
}
