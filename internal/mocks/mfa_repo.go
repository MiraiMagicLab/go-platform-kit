package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/domain"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/ports"
)

var _ ports.MFARepository = (*MFARepoMock)(nil)

// MFARepoMock is a mock implementation of ports.MFARepository for testing.
type MFARepoMock struct {
	UpsertTOTPSecretFunc     func(ctx context.Context, userID uuid.UUID, secret string) error
	GetMFAFunc               func(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error)
	EnableMFAFunc            func(ctx context.Context, userID uuid.UUID) error
	DisableMFAFunc           func(ctx context.Context, userID uuid.UUID) error
	ReplaceRecoveryCodesFunc func(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	UseRecoveryCodeFunc      func(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error)
	CleanupFunc              func(ctx context.Context, now time.Time) error
}

func (m *MFARepoMock) UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error {
	if m.UpsertTOTPSecretFunc != nil {
		return m.UpsertTOTPSecretFunc(ctx, userID, secret)
	}
	return nil
}

func (m *MFARepoMock) GetMFA(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error) {
	if m.GetMFAFunc != nil {
		return m.GetMFAFunc(ctx, userID)
	}
	return domain.MFAConfig{}, false, nil
}

func (m *MFARepoMock) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	if m.EnableMFAFunc != nil {
		return m.EnableMFAFunc(ctx, userID)
	}
	return nil
}

func (m *MFARepoMock) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	if m.DisableMFAFunc != nil {
		return m.DisableMFAFunc(ctx, userID)
	}
	return nil
}

func (m *MFARepoMock) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	if m.ReplaceRecoveryCodesFunc != nil {
		return m.ReplaceRecoveryCodesFunc(ctx, userID, codeHashes)
	}
	return nil
}

func (m *MFARepoMock) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	if m.UseRecoveryCodeFunc != nil {
		return m.UseRecoveryCodeFunc(ctx, userID, codeHash)
	}
	return false, nil
}

func (m *MFARepoMock) Cleanup(ctx context.Context, now time.Time) error {
	if m.CleanupFunc != nil {
		return m.CleanupFunc(ctx, now)
	}
	return nil
}
