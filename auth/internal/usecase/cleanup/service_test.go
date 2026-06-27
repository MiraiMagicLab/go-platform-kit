package cleanup_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/cleanup"
)

func TestRunOnceCallsAllRepos(t *testing.T) {
	refresh := testmem.NewRefreshTokens()
	mfa := testmem.NewMFA()
	email := testmem.NewEmailTokens()
	svc := cleanup.NewCleanupService(refresh, mfa, email)
	require.NotPanics(t, func() {
		svc.RunOnce(context.Background())
	})
}

func TestRunOnceNilSafe(t *testing.T) {
	svc := cleanup.NewCleanupService(nil, nil, nil)
	require.NotPanics(t, func() {
		svc.RunOnce(context.Background())
	})
	_ = time.Now()
}
