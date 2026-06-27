package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

// Cipher defines encryption/decryption for TOTP secrets at rest.
type Cipher interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

// MFAService handles TOTP MFA setup, verification, and recovery codes.
type MFAService struct {
	repo   store.MFARepository
	issuer string
	cipher Cipher
}

func NewMFAService(repo store.MFARepository, issuer string, cipher Cipher) *MFAService {
	return &MFAService{repo: repo, issuer: issuer, cipher: cipher}
}

func (s *MFAService) SetupTOTP(ctx context.Context, userID uuid.UUID, accountName string) (domain.MFASetup, error) {
	secret, err := randomBase32(20)
	if err != nil {
		return domain.MFASetup{}, err
	}
	secretToStore := secret
	if s.cipher != nil {
		enc, err := s.cipher.Encrypt(secret)
		if err != nil {
			return domain.MFASetup{}, err
		}
		secretToStore = enc
	}
	if err := s.repo.UpsertTOTPSecret(ctx, userID, secretToStore); err != nil {
		return domain.MFASetup{}, err
	}

	otpauthURL := totpProvisioningURL(s.issuer, accountName, secret)

	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		return domain.MFASetup{}, err
	}
	if err := s.repo.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return domain.MFASetup{}, err
	}

	return domain.MFASetup{
		Secret:        secret,
		OTPAuthURL:    otpauthURL,
		RecoveryCodes: codes,
	}, nil
}

func (s *MFAService) EnableTOTP(ctx context.Context, userID uuid.UUID, otpCode string) error {
	mfa, ok, err := s.repo.GetMFA(ctx, userID)
	if err != nil || !ok {
		return errors.New("mfa not setup")
	}
	secret := mfa.TOTPSecret
	if s.cipher != nil {
		dec, err := s.cipher.Decrypt(secret)
		if err != nil {
			return errors.New("invalid mfa secret")
		}
		secret = dec
	}
	if !totp.Validate(otpCode, secret) {
		return errors.New("invalid otp")
	}
	return s.repo.EnableMFA(ctx, userID)
}

func (s *MFAService) Disable(ctx context.Context, userID uuid.UUID) error {
	return s.repo.DisableMFA(ctx, userID)
}

func (s *MFAService) IsEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	mfa, ok, err := s.repo.GetMFA(ctx, userID)
	if err != nil || !ok {
		return false, err
	}
	return mfa.Enabled, nil
}

func (s *MFAService) Verify(ctx context.Context, userID uuid.UUID, otpCodeOrRecovery string) (bool, error) {
	mfa, ok, err := s.repo.GetMFA(ctx, userID)
	if err != nil || !ok || !mfa.Enabled {
		return false, nil
	}

	code := strings.ReplaceAll(strings.TrimSpace(otpCodeOrRecovery), " ", "")
	secret := mfa.TOTPSecret
	if s.cipher != nil {
		dec, err := s.cipher.Decrypt(secret)
		if err != nil {
			return false, err
		}
		secret = dec
	}
	if len(code) >= 6 && len(code) <= 8 && isDigits(code) {
		return totp.Validate(code, secret), nil
	}

	h := sha256Hex(code)
	return s.repo.UseRecoveryCode(ctx, userID, h)
}

func totpProvisioningURL(issuer, accountName, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		urlQueryEscape(issuer), urlQueryEscape(accountName), secret, urlQueryEscape(issuer))
}

func randomBase32(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func generateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	for i := 0; i < n; i++ {
		raw, err := randomHumanCode(10)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, raw)
		hashes = append(hashes, sha256Hex(raw))
	}
	return codes, hashes, nil
}

func randomHumanCode(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func urlQueryEscape(s string) string {
	r := strings.ReplaceAll(s, "%", "%25")
	r = strings.ReplaceAll(r, " ", "%20")
	r = strings.ReplaceAll(r, ":", "%3A")
	r = strings.ReplaceAll(r, "/", "%2F")
	r = strings.ReplaceAll(r, "?", "%3F")
	r = strings.ReplaceAll(r, "&", "%26")
	r = strings.ReplaceAll(r, "=", "%3D")
	return r
}
