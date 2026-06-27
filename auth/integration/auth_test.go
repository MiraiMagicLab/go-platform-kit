//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func TestAuthRegisterLoginFlow(t *testing.T) {
	ctx := context.Background()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}

	pg, err := postgres.Open(ctx, postgres.Config{URL: url})
	require.NoError(t, err)
	t.Cleanup(pg.Close)

	cfg := auth.DefaultConfig()
	cfg.JWTAccessSecret = "test-access-secret"
	cfg.JWTRefreshSecret = "test-refresh-secret"
	cfg.AccessTokenTTL = 15 * time.Minute
	cfg.RefreshTokenTTL = time.Hour

	mod, err := auth.New(ctx, auth.WithConfig(cfg), auth.WithPostgres(pg))
	require.NoError(t, err)
	require.NotNil(t, mod)
}
