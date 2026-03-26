package service

import (
	"context"
	"fmt"
	"time"

	"github.com/tienh/authsvc/internal/db"
)

type AccessTokenDenylist interface {
	IsDenied(ctx context.Context, jti string) (bool, error)
	Deny(ctx context.Context, jti string, ttl time.Duration) error
}

type NoopAccessTokenDenylist struct{}

func (NoopAccessTokenDenylist) IsDenied(context.Context, string) (bool, error) { return false, nil }
func (NoopAccessTokenDenylist) Deny(context.Context, string, time.Duration) error {
	return nil
}

type RedisAccessTokenDenylist struct {
	rdb db.RedisClient
}

func NewRedisAccessTokenDenylist(rdb db.RedisClient) *RedisAccessTokenDenylist {
	if rdb == nil {
		return nil
	}
	return &RedisAccessTokenDenylist{rdb: rdb}
}

func (d *RedisAccessTokenDenylist) IsDenied(ctx context.Context, jti string) (bool, error) {
	if d == nil || d.rdb == nil || jti == "" {
		return false, nil
	}
	_, err := d.rdb.Get(ctx, denyKey(jti)).Result()
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (d *RedisAccessTokenDenylist) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if d == nil || d.rdb == nil || jti == "" || ttl <= 0 {
		return nil
	}
	return d.rdb.Set(ctx, denyKey(jti), "1", ttl).Err()
}

func denyKey(jti string) string {
	return fmt.Sprintf("deny:access:%s", jti)
}
