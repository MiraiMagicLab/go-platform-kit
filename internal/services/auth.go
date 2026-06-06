package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/token"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
)

// ErrAccountLocked is returned when the account is temporarily locked due to too many failed attempts.
type ErrAccountLocked struct {
	Until *time.Time
}

func (e ErrAccountLocked) Error() string { return "account is locked" }

// ClientMeta carries client connection info stored on refresh-token / session rows (IP, User-Agent).
type ClientMeta struct {
	IP string
	UA string
}

type ErrUserBanned struct {
	Until  *time.Time
	Reason *string
}

func (e ErrUserBanned) Error() string { return "user is banned" }

type AuthService struct {
	users                *postgres.UserRepo
	refreshRepo          *postgres.RefreshTokenRepo
	mfaRepo              *postgres.MFARepo
	mfaVerifier          MFAVerifier
	denylist             AccessTokenDenylist
	jwt                  *token.JWTManager
	accessTTL            time.Duration
	refreshTTL           time.Duration
	issuer               string
	requireEmailVerified bool
	maxFailedAttempts   int
	lockDuration         time.Duration
}

func NewAuthService(
	users *postgres.UserRepo,
	refreshRepo *postgres.RefreshTokenRepo,
	mfaRepo *postgres.MFARepo,
	mfaVerifier MFAVerifier,
	denylist AccessTokenDenylist,
	jwt *token.JWTManager,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
	requireEmailVerified bool,
	maxFailedAttempts int,
	lockDuration time.Duration,
) *AuthService {
	if denylist == nil {
		denylist = NoopAccessTokenDenylist{}
	}
	if maxFailedAttempts <= 0 {
		maxFailedAttempts = 5
	}
	if lockDuration <= 0 {
		lockDuration = 15 * time.Minute
	}
	return &AuthService{
		users:                users,
		refreshRepo:          refreshRepo,
		mfaRepo:              mfaRepo,
		mfaVerifier:          mfaVerifier,
		denylist:             denylist,
		jwt:                  jwt,
		accessTTL:            accessTTL,
		refreshTTL:           refreshTTL,
		issuer:               issuer,
		requireEmailVerified: requireEmailVerified,
		maxFailedAttempts:    maxFailedAttempts,
		lockDuration:         lockDuration,
	}
}

type ErrEmailNotVerified struct{}

func (e ErrEmailNotVerified) Error() string { return "email not verified" }

type MFAVerifier interface {
	Verify(ctx context.Context, userID uuid.UUID, otpCodeOrRecovery string) (bool, error)
}

func (s *AuthService) Register(ctx context.Context, email, password string) (userID uuid.UUID, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, err
	}
	return s.users.Create(ctx, email, string(hash))
}

type LoginResult struct {
	UserID       uuid.UUID `json:"user_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	MFARequired  bool      `json:"mfa_required,omitempty"`
	MFAToken     string    `json:"mfa_token,omitempty"`
}

func (s *AuthService) Login(ctx context.Context, email, password string, meta ClientMeta) (LoginResult, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	if !u.PasswordLoginEnabled {
		return LoginResult{}, ErrInvalidCredentials
	}
	if isUserBanned(u.BannedUntil) {
		return LoginResult{}, ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if isAccountLocked(u.LockedUntil) {
		return LoginResult{}, ErrAccountLocked{Until: u.LockedUntil}
	}
	if isUserDeleted(u.DeletedAt) {
		return LoginResult{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		_ = s.users.IncrementFailedLogin(ctx, u.ID)
		u2, getErr := s.users.GetByID(ctx, u.ID)
		if getErr == nil && u2.FailedLoginCount+1 >= s.maxFailedAttempts {
			_ = s.users.SetLock(ctx, u.ID, time.Now().Add(s.lockDuration))
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	_ = s.users.ResetFailedLogin(ctx, u.ID)
	return s.StartSession(ctx, u.ID, meta, "")
}

func (s *AuthService) StartSession(ctx context.Context, userID uuid.UUID, meta ClientMeta, deviceName string) (LoginResult, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if isUserBanned(u.BannedUntil) {
		return LoginResult{}, ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if isAccountLocked(u.LockedUntil) {
		return LoginResult{}, ErrAccountLocked{Until: u.LockedUntil}
	}
	if isUserDeleted(u.DeletedAt) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if s.requireEmailVerified && !u.EmailVerified {
		return LoginResult{}, ErrEmailNotVerified{}
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

	access, _, err := s.jwt.NewAccessToken(u.ID, u.TokenVersion, sessionID, s.accessTTL)
	if err != nil {
		return LoginResult{}, err
	}
	refresh, _, err := s.jwt.NewRefreshToken(u.ID, u.TokenVersion, sessionID, s.refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}

	hash := hashToken(refresh)
	if _, err := s.refreshRepo.Create(ctx, u.ID, sessionID, hash, time.Now().Add(s.refreshTTL), meta.IP, meta.UA, deviceName); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID:       u.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *AuthService) CompleteMFA(ctx context.Context, mfaToken string, otpOrRecovery string, meta ClientMeta) (LoginResult, error) {
	if s.mfaRepo == nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	claims, err := s.jwt.ParseMFA(mfaToken)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil || claims.TokenVersion != u.TokenVersion {
		return LoginResult{}, ErrInvalidCredentials
	}

	m, ok, err := s.mfaRepo.GetMFA(ctx, userID)
	if err != nil || !ok || !m.Enabled {
		return LoginResult{}, ErrInvalidCredentials
	}

	if s.mfaVerifier == nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	okVerify, err := s.mfaVerifier.Verify(ctx, userID, strings.TrimSpace(otpOrRecovery))
	if err != nil || !okVerify {
		return LoginResult{}, ErrInvalidCredentials
	}

	return s.StartSession(ctx, userID, meta, "")
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string, meta ClientMeta, deviceName string) (LoginResult, error) {
	claims, err := s.jwt.ParseRefresh(refreshToken)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}

	rtHash := hashToken(refreshToken)
	oldRow, err := s.refreshRepo.GetByHash(ctx, rtHash)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}
	if oldRow.RevokedAt != nil || time.Now().After(oldRow.ExpiresAt) || oldRow.UserID != userID {
		return LoginResult{}, ErrInvalidRefresh
	}
	sessID := oldRow.SessionID
	if claims.SessionID != "" {
		csid, errP := uuid.Parse(claims.SessionID)
		if errP != nil || csid != sessID {
			return LoginResult{}, ErrInvalidRefresh
		}
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}
	if isUserBanned(u.BannedUntil) {
		return LoginResult{}, ErrInvalidRefresh
	}
	if claims.TokenVersion != u.TokenVersion {
		return LoginResult{}, ErrInvalidRefresh
	}

	newRefresh, _, err := s.jwt.NewRefreshToken(userID, u.TokenVersion, sessID, s.refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}
	newHash := hashToken(newRefresh)

	rotateRes, err := s.refreshRepo.Rotate(ctx, rtHash, newHash, time.Now().Add(s.refreshTTL), meta.IP, meta.UA, deviceName)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}
	if rotateRes.ReplayDetected {
		_ = s.users.IncrementTokenVersion(ctx, userID)
		return LoginResult{}, ErrInvalidRefresh
	}
	if rotateRes.Invalid || rotateRes.UserID != userID {
		return LoginResult{}, ErrInvalidRefresh
	}
	sessID = rotateRes.SessionID

	newAccess, _, err := s.jwt.NewAccessToken(userID, u.TokenVersion, sessID, s.accessTTL)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID:       userID,
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID, accessJTI string, accessExpiresAt time.Time) error {
	// Invalidate access tokens immediately (token_version in JWT claims).
	if err := s.users.IncrementTokenVersion(ctx, userID); err != nil {
		return err
	}
	// Revoke all refresh tokens for the user.
	if err := s.refreshRepo.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	ttl := time.Until(accessExpiresAt)
	if ttl > 0 {
		_ = s.denylist.Deny(ctx, accessJTI, ttl)
	}
	return nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func isUserBanned(until *time.Time) bool {
	return until != nil && time.Now().Before(*until)
}

func isAccountLocked(until *time.Time) bool {
	return until != nil && time.Now().Before(*until)
}

func isUserDeleted(deletedAt *time.Time) bool {
	return deletedAt != nil
}
