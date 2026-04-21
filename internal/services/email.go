package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
)

const (
	emailActionVerify      = "verify_email"
	emailActionReset       = "reset_password"
	resetDeliveryOTP  = "otp"
	resetDeliveryLink = "link"
)

type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

type EmailService struct {
	users       *postgres.UserRepo
	tokens      *postgres.EmailTokenRepo
	refreshRepo *postgres.RefreshTokenRepo
	sender      EmailSender
	publicBase  string
	verifyTTL   time.Duration
	resetTTL    time.Duration

	buildVerifyLink func(publicBaseURL, rawToken string) string
	buildResetLink  func(publicBaseURL, rawToken string) string
	renderVerify    func(link string) (subject string, body string)
	renderReset     func(link string) (subject string, body string)
	resetDelivery   string
}

type EmailHooks struct {
	BuildVerifyEmailLink   func(publicBaseURL, rawToken string) string
	BuildResetPasswordLink func(publicBaseURL, rawToken string) string
	RenderVerifyEmail      func(link string) (subject string, body string)
	RenderResetPassword    func(link string) (subject string, body string)
}

func NewEmailService(
	users *postgres.UserRepo,
	tokens *postgres.EmailTokenRepo,
	refresh *postgres.RefreshTokenRepo,
	sender EmailSender,
	publicBaseURL string,
	resetPasswordDelivery string,
	hooks EmailHooks,
) *EmailService {
	if hooks.BuildVerifyEmailLink == nil {
		hooks.BuildVerifyEmailLink = func(publicBase, raw string) string {
			return fmt.Sprintf("%s/auth/email/verify/confirm?token=%s", publicBase, url.QueryEscape(raw))
		}
	}
	if hooks.BuildResetPasswordLink == nil {
		hooks.BuildResetPasswordLink = func(publicBase, raw string) string {
			return fmt.Sprintf("%s/auth/password/reset/confirm?token=%s", publicBase, url.QueryEscape(raw))
		}
	}
	if hooks.RenderVerifyEmail == nil {
		hooks.RenderVerifyEmail = func(link string) (string, string) {
			return "Verify your email", "Verify your email by opening this link: " + link
		}
	}
	if hooks.RenderResetPassword == nil {
		hooks.RenderResetPassword = func(value string) (string, string) {
			if normalizeResetDelivery(resetPasswordDelivery) == resetDeliveryLink {
				return "Reset your password", "Reset your password by opening this link: " + value
			}
			return "Reset your password", "Your OTP code to reset password is: " + value
		}
	}

	return &EmailService{
		users:           users,
		tokens:          tokens,
		refreshRepo:     refresh,
		sender:          sender,
		publicBase:      publicBaseURL,
		verifyTTL:       24 * time.Hour,
		resetTTL:        30 * time.Minute,
		buildVerifyLink: hooks.BuildVerifyEmailLink,
		buildResetLink:  hooks.BuildResetPasswordLink,
		renderVerify:    hooks.RenderVerifyEmail,
		renderReset:     hooks.RenderResetPassword,
		resetDelivery:   normalizeResetDelivery(resetPasswordDelivery),
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
	link := s.buildVerifyLink(s.publicBase, raw)
	subject, body := s.renderVerify(link)
	return s.sender.Send(ctx, u.Email, subject, body)
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
	rawValue := ""
	hash := ""
	if s.resetDelivery == resetDeliveryLink {
		rawValue, hash, err = generateToken()
	} else {
		rawValue, hash, err = generateOTPCode()
	}
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, u.ID, emailActionReset, hash, time.Now().Add(s.resetTTL)); err != nil {
		return err
	}
	deliveryValue := rawValue
	if s.resetDelivery == resetDeliveryLink {
		deliveryValue = s.buildResetLink(s.publicBase, rawValue)
	}
	subject, body := s.renderReset(deliveryValue)
	return s.sender.Send(ctx, u.Email, subject, body)
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

func generateOTPCode() (code string, hashed string, err error) {
	var b [4]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	n := binary.BigEndian.Uint32(b[:]) % 1000000
	code = fmt.Sprintf("%06d", n)
	return code, sha256hex(code), nil
}

func normalizeResetDelivery(mode string) string {
	switch mode {
	case resetDeliveryLink:
		return resetDeliveryLink
	default:
		return resetDeliveryOTP
	}
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
