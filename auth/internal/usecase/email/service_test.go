package email_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/email"
)

type stubMailer struct {
	lastTo string
}

func (s *stubMailer) Send(ctx context.Context, to, subject, body string) error {
	s.lastTo = to
	return nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestConfirmVerifyEmail(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "user@example.com"})
	tokens := testmem.NewEmailTokens()
	raw := "verify-token-raw"
	tokens.StoreRawTokenForTest(userID, "verify_email", sha256hex(raw), time.Now().Add(time.Hour))

	svc := email.NewEmailService(users, tokens, testmem.NewRefreshTokens(), nil, "http://localhost", "otp", email.Hooks{})
	require.NoError(t, svc.ConfirmVerifyEmail(context.Background(), raw))

	u, err := users.GetByID(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, u.EmailVerified)
}

func TestForgotPasswordUnknownEmailIsSilent(t *testing.T) {
	mailer := &stubMailer{}
	svc := email.NewEmailService(testmem.NewUsers(), testmem.NewEmailTokens(), testmem.NewRefreshTokens(), mailer, "http://localhost", "otp", email.Hooks{})
	require.NoError(t, svc.ForgotPassword(context.Background(), "missing@example.com"))
	require.Empty(t, mailer.lastTo)
}

func TestResetPasswordIncrementsTokenVersion(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "user@example.com"})
	tokens := testmem.NewEmailTokens()
	refresh := testmem.NewRefreshTokens()
	raw := "reset-token"
	tokens.StoreRawTokenForTest(userID, "reset_password", sha256hex(raw), time.Now().Add(time.Hour))
	_, _ = refresh.Create(context.Background(), userID, uuid.New(), "hash", time.Now().Add(time.Hour), "", "", "")

	svc := email.NewEmailService(users, tokens, refresh, nil, "http://localhost", "otp", email.Hooks{})
	require.NoError(t, svc.ResetPassword(context.Background(), raw, "newpassword123"))

	u, err := users.GetByID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, 1, u.TokenVersion)
}

func TestRequestVerifyEmailRequiresSender(t *testing.T) {
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "user@example.com"})
	svc := email.NewEmailService(users, testmem.NewEmailTokens(), testmem.NewRefreshTokens(), nil, "http://localhost", "otp", email.Hooks{})
	require.Error(t, svc.RequestVerifyEmail(context.Background(), userID))
}
