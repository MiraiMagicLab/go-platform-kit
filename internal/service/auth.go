package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/tienh/authsvc/internal/repository"
	"github.com/tienh/authsvc/pkg/token"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
)

type AuthService struct {
	users       repository.UserRepository
	refreshRepo repository.RefreshTokenRepository
	mfaRepo     repository.MFARepository
	denylist    AccessTokenDenylist
	jwt         *token.JWTManager
	accessTTL   time.Duration
	refreshTTL  time.Duration
	issuer      string
}

func NewAuthService(
	users repository.UserRepository,
	refreshRepo repository.RefreshTokenRepository,
	mfaRepo repository.MFARepository,
	denylist AccessTokenDenylist,
	jwt *token.JWTManager,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	issuer string,
) *AuthService {
	if denylist == nil {
		denylist = NoopAccessTokenDenylist{}
	}
	return &AuthService{
		users:       users,
		refreshRepo: refreshRepo,
		mfaRepo:     mfaRepo,
		denylist:    denylist,
		jwt:         jwt,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
		issuer:      issuer,
	}
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

func (s *AuthService) Login(ctx context.Context, email, password string) (LoginResult, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	if !u.PasswordLoginEnabled {
		return LoginResult{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	return s.StartSession(ctx, u.ID)
}

func (s *AuthService) StartSession(ctx context.Context, userID uuid.UUID) (LoginResult, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
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

	access, _, err := s.jwt.NewAccessToken(u.ID, u.TokenVersion, s.accessTTL)
	if err != nil {
		return LoginResult{}, err
	}
	refresh, _, err := s.jwt.NewRefreshToken(u.ID, u.TokenVersion, s.refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}

	hash := hashToken(refresh)
	if _, err := s.refreshRepo.Create(ctx, u.ID, hash, time.Now().Add(s.refreshTTL)); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		UserID:       u.ID,
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *AuthService) CompleteMFA(ctx context.Context, mfaToken string, otpOrRecovery string) (LoginResult, error) {
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

	okTotp := totp.Validate(strings.TrimSpace(otpOrRecovery), m.TOTPSecret)
	if !okTotp {
		h := hashToken(strings.TrimSpace(otpOrRecovery))
		used, err := s.mfaRepo.UseRecoveryCode(ctx, userID, h)
		if err != nil || !used {
			return LoginResult{}, ErrInvalidCredentials
		}
	}

	return s.StartSession(ctx, userID)
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (LoginResult, error) {
	claims, err := s.jwt.ParseRefresh(refreshToken)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}

	rtHash := hashToken(refreshToken)
	newRefresh, _, err := s.jwt.NewRefreshToken(userID, claims.TokenVersion, s.refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}
	newHash := hashToken(newRefresh)

	rotateRes, err := s.refreshRepo.Rotate(ctx, rtHash, newHash, time.Now().Add(s.refreshTTL))
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

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, ErrInvalidRefresh
	}
	if claims.TokenVersion != u.TokenVersion {
		return LoginResult{}, ErrInvalidRefresh
	}

	newAccess, _, err := s.jwt.NewAccessToken(userID, u.TokenVersion, s.accessTTL)
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
