package services

import (
	"context"
	"time"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
)

type CleanupService struct {
	refresh *postgres.RefreshTokenRepo
	mfa     *postgres.MFARepo
	email   *postgres.EmailTokenRepo
}

func NewCleanupService(refresh *postgres.RefreshTokenRepo, mfa *postgres.MFARepo, email *postgres.EmailTokenRepo) *CleanupService {
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
