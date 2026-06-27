package cleanup

import (
	"context"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
	"time"
)

// CleanupService periodically purges expired/revoked data.
type CleanupService struct {
	refresh store.RefreshTokenRepository
	mfa     store.MFARepository
	email   store.EmailTokenRepository
}

func NewCleanupService(refresh store.RefreshTokenRepository, mfa store.MFARepository, email store.EmailTokenRepository) *CleanupService {
	return &CleanupService{refresh: refresh, mfa: mfa, email: email}
}

func (s *CleanupService) RunOnce(ctx context.Context) {
	now := time.Now()
	if s.refresh != nil {
		_ = s.refresh.Cleanup(ctx, now)
	}
	if s.mfa != nil {
		_ = s.mfa.Cleanup(ctx, now)
	}
	if s.email != nil {
		_ = s.email.Cleanup(ctx, now)
	}
}
