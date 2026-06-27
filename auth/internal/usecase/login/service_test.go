package login_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	mfa "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/mfa"
)

func TestLoginIssuesTokensAndCreatesSession(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	users := testmem.NewUsers()
	id := uuid.New()
	users.SetUser(id, domain.User{
		ID: id, Email: "user@example.com", PasswordHash: string(hash), PasswordLoginEnabled: true,
	})
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := testmem.NewLoginService(t, users, sessions, refresh, nil, nil)

	res, err := svc.Login(context.Background(), "user@example.com", "password123", domain.ClientMeta{IP: "127.0.0.1"})
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.Len(t, sessions.Created(), 1)
}

func TestStartSessionIssuesTokens(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "user@example.com", PasswordLoginEnabled: true})
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := testmem.NewLoginService(t, users, sessions, refresh, nil, nil)

	res, err := svc.StartSession(context.Background(), userID, domain.ClientMeta{}, "")
	require.NoError(t, err)
	require.False(t, res.MFARequired)
	require.NotEmpty(t, res.AccessToken)
	require.Len(t, sessions.Created(), 1)
}

func TestLogoutRevokesCurrentSessionOnly(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "a@b.c"})
	svc := testmem.NewLoginService(t, users, sessions, refresh, nil, nil)

	require.NoError(t, svc.Logout(context.Background(), userID, sessionID, "jti", time.Now().Add(time.Minute)))
}

func TestLoginReturnsMFAChallengeWhenEnabled(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{
		ID: userID, Email: "mfa@example.com", PasswordHash: string(hash), PasswordLoginEnabled: true,
	})
	mfaRepo := testmem.NewMFA()
	require.NoError(t, mfaRepo.UpsertTOTPSecret(context.Background(), userID, "JBSWY3DPEHPK3PXP"))
	require.NoError(t, mfaRepo.EnableMFA(context.Background(), userID))

	svc := testmem.NewLoginService(t, users, testmem.NewSessions(), testmem.NewRefreshTokens(), mfaRepo, mfa.NewMFAService(mfaRepo, "test", nil))

	res, err := svc.Login(context.Background(), "mfa@example.com", "password123", domain.ClientMeta{})
	require.NoError(t, err)
	require.True(t, res.MFARequired)
	require.NotEmpty(t, res.MFAToken)
	require.Empty(t, res.AccessToken)
}

func TestCompleteMFAIssuesTokens(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP"
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{
		ID: userID, Email: "mfa@example.com", PasswordHash: string(hash), PasswordLoginEnabled: true,
	})
	mfaRepo := testmem.NewMFA()
	require.NoError(t, mfaRepo.UpsertTOTPSecret(context.Background(), userID, secret))
	require.NoError(t, mfaRepo.EnableMFA(context.Background(), userID))
	mfaSvc := mfa.NewMFAService(mfaRepo, "test", nil)
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := testmem.NewLoginService(t, users, sessions, refresh, mfaRepo, mfaSvc)

	challenge, err := svc.Login(context.Background(), "mfa@example.com", "password123", domain.ClientMeta{})
	require.NoError(t, err)
	require.True(t, challenge.MFARequired)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	res, err := svc.CompleteMFA(context.Background(), challenge.MFAToken, code, domain.ClientMeta{IP: "127.0.0.1"})
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.Len(t, sessions.Created(), 1)
}

func TestRefreshRotatesTokens(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{
		ID: userID, Email: "user@example.com", PasswordHash: string(hash), PasswordLoginEnabled: true,
	})
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := testmem.NewLoginService(t, users, sessions, refresh, nil, nil)

	loginRes, err := svc.Login(context.Background(), "user@example.com", "password123", domain.ClientMeta{})
	require.NoError(t, err)

	refreshRes, err := svc.Refresh(context.Background(), loginRes.RefreshToken, domain.ClientMeta{}, "")
	require.NoError(t, err)
	require.NotEmpty(t, refreshRes.AccessToken)
	require.NotEmpty(t, refreshRes.RefreshToken)
	require.NotEqual(t, loginRes.RefreshToken, refreshRes.RefreshToken)

	_, err = svc.Refresh(context.Background(), loginRes.RefreshToken, domain.ClientMeta{}, "")
	require.Error(t, err)
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{
		ID: userID, Email: "user@example.com", PasswordHash: string(hash), PasswordLoginEnabled: true,
	})
	svc := testmem.NewLoginService(t, users, testmem.NewSessions(), testmem.NewRefreshTokens(), nil, nil)

	_, err := svc.Login(context.Background(), "user@example.com", "wrong", domain.ClientMeta{})
	require.ErrorIs(t, err, domain.ErrInvalidCredentials)
}
