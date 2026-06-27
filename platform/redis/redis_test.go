package redis_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/platform/redis"
)

func TestConfigValidate(t *testing.T) {
	err := redis.Config{}.Validate()
	require.Error(t, err)

	require.NoError(t, redis.Config{URL: "redis://localhost:6379"}.Validate())
	require.NoError(t, redis.Config{Addr: "localhost:6379"}.Validate())
}
