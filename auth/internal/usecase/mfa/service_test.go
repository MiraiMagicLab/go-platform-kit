package mfa_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/mfa"
)

func TestSetupEnableAndVerifyTOTP(t *testing.T) {
	userID := uuid.New()
	repo := testmem.NewMFA()
	svc := mfa.NewMFAService(repo, "test-issuer", nil)

	setup, err := svc.SetupTOTP(context.Background(), userID, "user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, setup.Secret)
	require.NotEmpty(t, setup.OTPAuthURL)
	require.Len(t, setup.RecoveryCodes, 10)

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, svc.EnableTOTP(context.Background(), userID, code))

	enabled, err := svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, enabled)

	ok, err := svc.Verify(context.Background(), userID, code)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerifyRecoveryCode(t *testing.T) {
	userID := uuid.New()
	repo := testmem.NewMFA()
	svc := mfa.NewMFAService(repo, "test", nil)

	setup, err := svc.SetupTOTP(context.Background(), userID, "user@example.com")
	require.NoError(t, err)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, svc.EnableTOTP(context.Background(), userID, code))

	recovery := setup.RecoveryCodes[0]
	ok, err := svc.Verify(context.Background(), userID, recovery)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = svc.Verify(context.Background(), userID, recovery)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDisableMFA(t *testing.T) {
	userID := uuid.New()
	repo := testmem.NewMFA()
	svc := mfa.NewMFAService(repo, "test", nil)

	setup, err := svc.SetupTOTP(context.Background(), userID, "user@example.com")
	require.NoError(t, err)
	code, _ := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, svc.EnableTOTP(context.Background(), userID, code))

	require.NoError(t, svc.Disable(context.Background(), userID))
	enabled, err := svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.False(t, enabled)
}
