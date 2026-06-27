package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

var _ store.MFARepository = (*MFAAdapter)(nil)

// MFAAdapter wraps *MFARepo to implement store.MFARepository.
type MFAAdapter struct {
	repo *MFARepo
}

func NewMFAAdapter(repo *MFARepo) *MFAAdapter {
	return &MFAAdapter{repo: repo}
}

func (a *MFAAdapter) UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error {
	return a.repo.UpsertTOTPSecret(ctx, userID, secret)
}

func (a *MFAAdapter) GetMFA(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error) {
	dto, ok, err := a.repo.GetMFA(ctx, userID)
	if err != nil {
		return domain.MFAConfig{}, false, err
	}
	if !ok {
		return domain.MFAConfig{}, false, nil
	}
	return domain.MFAConfig{
		UserID:     dto.UserID,
		TOTPSecret: dto.TOTPSecret,
		Enabled:    dto.Enabled,
		EnabledAt:  dto.EnabledAt,
		CreatedAt:  dto.CreatedAt,
	}, true, nil
}

func (a *MFAAdapter) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	return a.repo.EnableMFA(ctx, userID)
}

func (a *MFAAdapter) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	return a.repo.DisableMFA(ctx, userID)
}

func (a *MFAAdapter) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	return a.repo.ReplaceRecoveryCodes(ctx, userID, codeHashes)
}

func (a *MFAAdapter) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	return a.repo.UseRecoveryCode(ctx, userID, codeHash)
}

func (a *MFAAdapter) Cleanup(ctx context.Context, now time.Time) error {
	return a.repo.Cleanup(ctx, now)
}
