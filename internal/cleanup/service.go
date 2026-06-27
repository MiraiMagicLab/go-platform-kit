package cleanup

import (
	"context"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

// CleanupService periodically purges expired/revoked data.
type CleanupService struct {
	refresh ports.RefreshTokenRepository
	mfa     ports.MFARepository
	email   ports.EmailTokenRepository
}

// NewCleanupService creates a CleanupService that purges expired tokens and data
// from the provided repositories.
func NewCleanupService(refresh ports.RefreshTokenRepository, mfa ports.MFARepository, email ports.EmailTokenRepository) *CleanupService {
	return &CleanupService{refresh: refresh, mfa: mfa, email: email}
}

// RunOnce executes a single cleanup pass, purging expired refresh tokens, MFA recovery
// codes, and email action tokens. Errors from individual repositories are silently ignored.
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
