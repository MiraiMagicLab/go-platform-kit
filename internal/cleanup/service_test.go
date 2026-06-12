package cleanup_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/cleanup"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/mocks"
)

func TestCleanupService_RunOnce(t *testing.T) {
	refreshCalled := false
	mfaCalled := false
	emailCalled := false

	refresh := &mocks.RefreshTokenRepoMock{
		CleanupFunc: func(ctx context.Context, now time.Time) error {
			refreshCalled = true
			return nil
		},
	}
	mfa := &mocks.MFARepoMock{
		CleanupFunc: func(ctx context.Context, now time.Time) error {
			mfaCalled = true
			return nil
		},
	}
	email := &mocks.EmailTokenRepoMock{
		CleanupFunc: func(ctx context.Context, now time.Time) error {
			emailCalled = true
			return nil
		},
	}

	svc := cleanup.NewCleanupService(refresh, mfa, email)
	svc.RunOnce(context.Background())

	assert.True(t, refreshCalled)
	assert.True(t, mfaCalled)
	assert.True(t, emailCalled)
}

func TestCleanupService_RunOnce_NilRepos(t *testing.T) {
	svc := cleanup.NewCleanupService(nil, nil, nil)
	svc.RunOnce(context.Background()) // should not panic
}
