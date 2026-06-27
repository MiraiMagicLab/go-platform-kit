package health

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

// PostgresChecker pings a Postgres pool.
type PostgresChecker struct {
	Pool *pgxpool.Pool
}

func (c PostgresChecker) Name() string { return "postgres" }

func (c PostgresChecker) Check(ctx context.Context) error {
	return postgres.Ping(ctx, c.Pool)
}

// RedisChecker pings a Redis client.
type RedisChecker struct {
	Client *goredis.Client
}

func (c RedisChecker) Name() string { return "redis" }

func (c RedisChecker) Check(ctx context.Context) error {
	return redis.Ping(ctx, c.Client)
}
