package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/token"
)

// MFAVerifier verifies TOTP codes or recovery codes.
type MFAVerifier interface {
	Verify(ctx context.Context, userID uuid.UUID, otpCodeOrRecovery string) (bool, error)
}

// Config holds configuration for AuthService.
type Config struct {
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	Issuer                 string
	RequireEmailVerified   bool
	MaxFailedLoginAttempts int
	AccountLockDuration    time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        720 * time.Hour,
		Issuer:                 "authkit",
		RequireEmailVerified:   false,
		MaxFailedLoginAttempts: 5,
		AccountLockDuration:    15 * time.Minute,
	}
}

// AuthService handles authentication: register, login, refresh, logout, MFA.
type AuthService struct {
	users       ports.UserRepository
	refreshRepo ports.RefreshTokenRepository
	mfaRepo     ports.MFARepository
	mfaVerifier MFAVerifier
	denylist    ports.AccessTokenDenylist
	jwt         *token.JWTManager
	cfg         Config
}

// LoginResult contains the outcome of a successful login or refresh.
type LoginResult struct {
	UserID       uuid.UUID `json:"user_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	MFARequired  bool      `json:"mfa_required,omitempty"`
	MFAToken     string    `json:"mfa_token,omitempty"`
}

// NewAuthService creates a new AuthService with the given dependencies.
func NewAuthService(
	users ports.UserRepository,
	refreshRepo ports.RefreshTokenRepository,
	mfaRepo ports.MFARepository,
	mfaVerifier MFAVerifier,
	denylist ports.AccessTokenDenylist,
	jwtManager *token.JWTManager,
	cfg Config,
) *AuthService {
	if denylist == nil {
		denylist = ports.NoopAccessTokenDenylist{}
	}
	if cfg.MaxFailedLoginAttempts <= 0 {
		cfg.MaxFailedLoginAttempts = 5
	}
	if cfg.AccountLockDuration <= 0 {
		cfg.AccountLockDuration = 15 * time.Minute
	}
	return &AuthService{
		users:       users,
		refreshRepo: refreshRepo,
		mfaRepo:     mfaRepo,
		mfaVerifier: mfaVerifier,
		denylist:    denylist,
		jwt:         jwtManager,
		cfg:         cfg,
	}
}

// Register creates a new user with the given email and password.
func (s *AuthService) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, err
	}
	return s.users.Create(ctx, email, string(hash))
}

// Login authenticates a user by email and password, returning tokens or an MFA challenge.
func (s *AuthService) Login(ctx context.Context, email, password string, meta domain.ClientMeta) (LoginResult, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	if !u.PasswordLoginEnabled {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	if u.IsBanned() {
		return LoginResult{}, domain.ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if u.IsLocked() {
		return LoginResult{}, domain.ErrAccountLocked{Until: u.LockedUntil}
	}
	if u.IsDeleted() {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		_ = s.users.IncrementFailedLogin(ctx, u.ID)
		u2, getErr := s.users.GetByID(ctx, u.ID)
		if getErr == nil && u2.FailedLoginCount+1 >= s.cfg.MaxFailedLoginAttempts {
			_ = s.users.SetLock(ctx, u.ID, time.Now().Add(s.cfg.AccountLockDuration))
		}
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	_ = s.users.ResetFailedLogin(ctx, u.ID)
	return s.StartSession(ctx, u.ID, meta, "")
}

// StartSession creates a new session and issues tokens. If MFA is enabled, returns an MFA challenge.
func (s *AuthService) StartSession(ctx context.Context, userID uuid.UUID, meta domain.ClientMeta, deviceName string) (LoginResult, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	if u.IsBanned() {
		return LoginResult{}, domain.ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if u.IsLocked() {
		return LoginResult{}, domain.ErrAccountLocked{Until: u.LockedUntil}
	}
	if u.IsDeleted() {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	if s.cfg.RequireEmailVerified && !u.EmailVerified {
		return LoginResult{}, domain.ErrEmailNotVerified{}
	}

	// If MFA is enabled, return MFA challenge token instead of access/refresh.
	if s.mfaRepo != nil {
		m, ok, err := s.mfaRepo.GetMFA(ctx, u.ID)
		if err == nil && ok && m.Enabled {
			mfaTok, _, err := s.jwt.NewMFAToken(u.ID, u.TokenVersion, 5*time.Minute)
			if err != nil {
				return LoginResult{}, err
			}
			return LoginResult{
				UserID:      u.ID,
				MFARequired: true,
				MFAToken:    mfaTok,
			}, nil
		}
	}

	sessionID := uuid.New()

	access, _, err := s.jwt.NewAccessToken(u.ID, u.TokenVersion, sessionID, s.cfg.AccessTokenTTL)
	if err != nil {
		return LoginResult{}, err
	}
	refresh, _, err := s.jwt.NewRefreshToken(u.ID, u.TokenVersion, sessionID, s.cfg.RefreshTokenTTL)
	if err != nil {
		return LoginResult{}, err
	}

	hash := HashToken(refresh)
	if _, err := s.refreshRepo.Create(ctx, u.ID, sessionID, hash, time.Now().Add(s.cfg.RefreshTokenTTL), meta.IP, meta.UA, deviceName); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID:       u.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// CompleteMFA verifies an MFA token and OTP code, then issues real tokens.
func (s *AuthService) CompleteMFA(ctx context.Context, mfaToken string, otpOrRecovery string, meta domain.ClientMeta) (LoginResult, error) {
	if s.mfaRepo == nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	claims, err := s.jwt.ParseMFA(mfaToken)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil || claims.TokenVersion != u.TokenVersion {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	m, ok, err := s.mfaRepo.GetMFA(ctx, userID)
	if err != nil || !ok || !m.Enabled {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	if s.mfaVerifier == nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	okVerify, err := s.mfaVerifier.Verify(ctx, userID, strings.TrimSpace(otpOrRecovery))
	if err != nil || !okVerify {
		return LoginResult{}, domain.ErrInvalidCredentials
	}

	return s.StartSession(ctx, userID, meta, "")
}

// Refresh rotates a refresh token and issues new access/refresh tokens.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string, meta domain.ClientMeta, deviceName string) (LoginResult, error) {
	claims, err := s.jwt.ParseRefresh(refreshToken)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidRefresh
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidRefresh
	}

	rtHash := HashToken(refreshToken)
	oldRow, err := s.refreshRepo.GetByHash(ctx, rtHash)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	if oldRow.IsRevoked() || oldRow.IsExpired() || oldRow.UserID != userID {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	sessID := oldRow.SessionID
	if claims.SessionID != "" {
		csid, errP := uuid.Parse(claims.SessionID)
		if errP != nil || csid != sessID {
			return LoginResult{}, domain.ErrInvalidRefresh
		}
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	if u.IsBanned() {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	if claims.TokenVersion != u.TokenVersion {
		return LoginResult{}, domain.ErrInvalidRefresh
	}

	newRefresh, _, err := s.jwt.NewRefreshToken(userID, u.TokenVersion, sessID, s.cfg.RefreshTokenTTL)
	if err != nil {
		return LoginResult{}, err
	}
	newHash := HashToken(newRefresh)

	rotateRes, err := s.refreshRepo.Rotate(ctx, rtHash, newHash, time.Now().Add(s.cfg.RefreshTokenTTL), meta.IP, meta.UA, deviceName)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	if rotateRes.ReplayDetected {
		_ = s.users.IncrementTokenVersion(ctx, userID)
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	if rotateRes.Invalid || rotateRes.UserID != userID {
		return LoginResult{}, domain.ErrInvalidRefresh
	}
	sessID = rotateRes.SessionID

	newAccess, _, err := s.jwt.NewAccessToken(userID, u.TokenVersion, sessID, s.cfg.AccessTokenTTL)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID:       userID,
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	}, nil
}

// Logout invalidates all tokens for a user by incrementing the token version.
func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID, accessJTI string, accessExpiresAt time.Time) error {
	if err := s.users.IncrementTokenVersion(ctx, userID); err != nil {
		return err
	}
	if err := s.refreshRepo.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	ttl := time.Until(accessExpiresAt)
	if ttl > 0 {
		_ = s.denylist.Deny(ctx, accessJTI, ttl)
	}
	return nil
}

// HashToken computes the SHA-256 hash of a token string.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
