//go:build integration

package redis_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	redisstore "github.com/MiraiMagicLab/go-platform-kit/auth/internal/redis"
	platformredis "github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

func openRedis(t *testing.T) (*redisstore.UserAuthCache, func()) {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	ctx := context.Background()
	rdb, err := platformredis.Open(ctx, platformredis.Config{URL: url})
	require.NoError(t, err)
	cache := redisstore.NewUserAuthCache(rdb, time.Minute)
	require.NotNil(t, cache)
	return cache, func() { _ = platformredis.Close(rdb) }
}

func TestUserAuthCacheSetGetDel(t *testing.T) {
	cache, cleanup := openRedis(t)
	defer cleanup()
	ctx := context.Background()

	userID := uuid.New()
	user := domain.User{ID: userID, Email: "cache@example.com", TokenVersion: 3}

	_, ok, err := cache.Get(ctx, userID)
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, cache.Set(ctx, user))
	got, ok, err := cache.Get(ctx, userID)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 3, got.TokenVersion)

	require.NoError(t, cache.Del(ctx, userID))
	_, ok, err = cache.Get(ctx, userID)
	require.NoError(t, err)
	require.False(t, ok)
}
