package config

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
	"github.com/MiraiMagicLab/go-platform-kit/platform/storage"
)

// InfraClients holds opened infrastructure clients for a host application.
type InfraClients struct {
	Postgres *pgxpool.Pool
	Redis    *goredis.Client
	Mail     mail.Mailer
	Storage  storage.ObjectStore
}

// OpenInfra opens all configured infrastructure clients from cfg.Infra.
func (c Config) OpenInfra(ctx context.Context) (InfraClients, error) {
	var out InfraClients

	if c.Infra.Postgres.IsConfigured() {
		pg, err := postgres.Open(ctx, c.Infra.Postgres)
		if err != nil {
			return InfraClients{}, fmt.Errorf("config: postgres: %w", err)
		}
		out.Postgres = pg
	}
	if c.Infra.Redis.IsConfigured() {
		rdb, err := redis.Open(ctx, c.Infra.Redis)
		if err != nil {
			out.Close()
			return InfraClients{}, fmt.Errorf("config: redis: %w", err)
		}
		out.Redis = rdb
	}
	if c.Infra.Mail.IsConfigured() {
		sender, err := mail.Open(c.Infra.Mail)
		if err != nil {
			out.Close()
			return InfraClients{}, fmt.Errorf("config: mail: %w", err)
		}
		out.Mail = sender
	}
	if c.Infra.Storage.IsConfigured() {
		store, err := storage.Open(ctx, c.Infra.Storage)
		if err != nil {
			out.Close()
			return InfraClients{}, fmt.Errorf("config: storage: %w", err)
		}
		out.Storage = store
	}
	return out, nil
}

// Close releases all opened clients.
func (c InfraClients) Close() {
	postgres.Close(c.Postgres)
	if c.Redis != nil {
		_ = redis.Close(c.Redis)
	}
}

// Ping verifies connectivity for all opened clients.
func (c InfraClients) Ping(ctx context.Context) error {
	if c.Postgres != nil {
		if err := postgres.Ping(ctx, c.Postgres); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
	}
	if c.Redis != nil {
		if err := redis.Ping(ctx, c.Redis); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
	}
	return nil
}
