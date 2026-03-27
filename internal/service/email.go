package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/tienh/authsvc/internal/repository"
)

const (
	emailActionVerify = "verify_email"
	emailActionReset  = "reset_password"
)

type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

type EmailService struct {
	users       repository.UserRepository
	tokens      repository.EmailTokenRepository
	refreshRepo repository.RefreshTokenRepository
	sender      EmailSender
	publicBase  string
	verifyTTL   time.Duration
	resetTTL    time.Duration
}

func NewEmailService(
	users repository.UserRepository,
	tokens repository.EmailTokenRepository,
	refresh repository.RefreshTokenRepository,
	sender EmailSender,
	publicBaseURL string,
) *EmailService {
	return &EmailService{
		users:       users,
		tokens:      tokens,
		refreshRepo: refresh,
		sender:      sender,
		publicBase:  publicBaseURL,
		verifyTTL:   24 * time.Hour,
		resetTTL:    30 * time.Minute,
	}
}

func (s *EmailService) RequestVerifyEmail(ctx context.Context, userID uuid.UUID) error {
	if s.sender == nil {
		return fmt.Errorf("email sender not configured")
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	raw, hash, err := generateToken()
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, userID, emailActionVerify, hash, time.Now().Add(s.verifyTTL)); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/auth/email/verify/confirm?token=%s", s.publicBase, url.QueryEscape(raw))
	body := "Verify your email by opening this link: " + link
	return s.sender.Send(ctx, u.Email, "Verify your email", body)
}

func (s *EmailService) ConfirmVerifyEmail(ctx context.Context, rawToken string) error {
	userID, ok, err := s.tokens.Consume(ctx, emailActionVerify, sha256hex(rawToken), time.Now())
	if err != nil || !ok {
		return fmt.Errorf("invalid token")
	}
	return s.users.SetEmailVerified(ctx, userID, true)
}

func (s *EmailService) ForgotPassword(ctx context.Context, email string) error {
	if s.sender == nil {
		return fmt.Errorf("email sender not configured")
	}
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		// do not leak user existence
		return nil
	}
	raw, hash, err := generateToken()
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, u.ID, emailActionReset, hash, time.Now().Add(s.resetTTL)); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/auth/password/reset/confirm?token=%s", s.publicBase, url.QueryEscape(raw))
	body := "Reset your password by opening this link: " + link
	return s.sender.Send(ctx, u.Email, "Reset your password", body)
}

func (s *EmailService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	userID, ok, err := s.tokens.Consume(ctx, emailActionReset, sha256hex(rawToken), time.Now())
	if err != nil || !ok {
		return fmt.Errorf("invalid token")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.users.SetPassword(ctx, userID, string(hash)); err != nil {
		return err
	}
	_ = s.users.IncrementTokenVersion(ctx, userID)
	_ = s.refreshRepo.RevokeAllForUser(ctx, userID)
	return nil
}

func generateToken() (raw string, hashed string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, sha256hex(raw), nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
