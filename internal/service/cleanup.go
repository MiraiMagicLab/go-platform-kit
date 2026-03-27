package service

import (
	"context"
	"time"

	"github.com/tienh/authsvc/internal/repository"
)

type CleanupService struct {
	refresh repository.RefreshTokenRepository
	mfa     repository.MFARepository
	email   repository.EmailTokenRepository
}

func NewCleanupService(refresh repository.RefreshTokenRepository, mfa repository.MFARepository, email repository.EmailTokenRepository) *CleanupService {
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
