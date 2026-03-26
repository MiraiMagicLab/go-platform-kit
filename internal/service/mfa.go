package service

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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/tienh/authsvc/internal/repository"
)

var ErrMFARequired = errors.New("mfa required")

type MFAService struct {
	repo   repository.MFARepository
	issuer string
	cipher StringCipher
}

type StringCipher interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

func NewMFAService(repo repository.MFARepository, issuer string, cipher StringCipher) *MFAService {
	return &MFAService{repo: repo, issuer: issuer, cipher: cipher}
}

type MFASetup struct {
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

func (s *MFAService) SetupTOTP(ctx context.Context, userID uuid.UUID, accountName string) (MFASetup, error) {
	secret, err := randomBase32(20)
	if err != nil {
		return MFASetup{}, err
	}
	secretToStore := secret
	if s.cipher != nil {
		enc, err := s.cipher.Encrypt(secret)
		if err != nil {
			return MFASetup{}, err
		}
		secretToStore = enc
	}
	if err := s.repo.UpsertTOTPSecret(ctx, userID, secretToStore); err != nil {
		return MFASetup{}, err
	}

	key, err := otp.NewKeyFromURL(totpProvisioningURL(s.issuer, accountName, secret))
	if err != nil {
		return MFASetup{}, err
	}

	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		return MFASetup{}, err
	}
	if err := s.repo.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return MFASetup{}, err
	}

	return MFASetup{
		Secret:        secret,
		OTPAuthURL:    key.URL(),
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
	ok2 := totp.Validate(otpCode, secret)
	if !ok2 {
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
	// otpauth://totp/{issuer}:{account}?secret=...&issuer=...
	issuerEsc := urlQueryEscape(issuer)
	accountEsc := urlQueryEscape(accountName)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuerEsc, accountEsc, secret, issuerEsc)
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
	// minimal escape without adding a new dependency; good enough for issuer/account.
	r := strings.ReplaceAll(s, "%", "%25")
	r = strings.ReplaceAll(r, " ", "%20")
	r = strings.ReplaceAll(r, ":", "%3A")
	r = strings.ReplaceAll(r, "/", "%2F")
	r = strings.ReplaceAll(r, "?", "%3F")
	r = strings.ReplaceAll(r, "&", "%26")
	r = strings.ReplaceAll(r, "=", "%3D")
	return r
}

// Keep dependency footprint small: otp.NewKeyFromURL already validates format.
var _ = otp.AlgorithmSHA1
