package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-auth-lib/internal/auth"
	"github.com/MiraiMagicLab/go-auth-lib/internal/mocks"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/domain"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/token"
)

const (
	testAccessSecret  = "test-access-secret-32bytes-long!!"
	testRefreshSecret = "test-refresh-secret-32bytes-long!"
	testIssuer        = "test"
)

func newTestJWTManager() *token.JWTManager {
	return token.NewJWTManager(testAccessSecret, testRefreshSecret, testIssuer)
}

func newTestConfig() auth.Config {
	return auth.Config{
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        720 * time.Hour,
		Issuer:                 testIssuer,
		RequireEmailVerified:   false,
		MaxFailedLoginAttempts: 5,
		AccountLockDuration:    15 * time.Minute,
	}
}

func hashPassword(pw string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(hash)
}

func validUser(id uuid.UUID, email, password string) domain.User {
	now := time.Now()
	return domain.User{
		ID:                   id,
		Email:                email,
		PasswordHash:         hashPassword(password),
		EmailVerified:        true,
		PasswordLoginEnabled: true,
		TokenVersion:         0,
		FailedLoginCount:     0,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// --- Register Tests ---

func TestAuthService_Register_Success(t *testing.T) {
	userID := uuid.New()
	users := &mocks.UserRepoMock{
		CreateFunc: func(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
			return userID, nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	id, err := svc.Register(context.Background(), "test@example.com", "password123")

	require.NoError(t, err)
	assert.Equal(t, userID, id)
	assert.Len(t, users.CreateCalls, 1)
	assert.Equal(t, "test@example.com", users.CreateCalls[0].Email)
	// Verify password was hashed (not stored as plaintext)
	assert.NotEqual(t, "password123", users.CreateCalls[0].PasswordHash)
}

// --- Login Tests ---

func TestAuthService_Login_Success(t *testing.T) {
	userID := uuid.New()
	email := "test@example.com"
	password := "password123"

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return validUser(userID, email, password), nil
		},
		GetByIDFunc: func(ctx context.Context, id uuid.UUID) (domain.User, error) {
			return validUser(userID, email, password), nil
		},
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{}

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, nil, newTestJWTManager(), newTestConfig())
	result, err := svc.Login(context.Background(), email, password, domain.ClientMeta{IP: "127.0.0.1", UA: "test"})

	require.NoError(t, err)
	assert.Equal(t, userID, result.UserID)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.False(t, result.MFARequired)
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	userID := uuid.New()
	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return validUser(userID, "test@example.com", "correct-password"), nil
		},
		IncrementFailedLoginFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "wrong-password", domain.ClientMeta{})

	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_UnknownEmail(t *testing.T) {
	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return domain.User{}, assert.AnError
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "unknown@example.com", "password", domain.ClientMeta{})

	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_PasswordLoginDisabled(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")
	u.PasswordLoginEnabled = false

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_BannedUser(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")
	future := time.Now().Add(24 * time.Hour)
	u.BannedUntil = &future
	reason := "violation"
	u.BanReason = &reason

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	var banErr domain.ErrUserBanned
	assert.ErrorAs(t, err, &banErr)
}

func TestAuthService_Login_LockedAccount(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")
	future := time.Now().Add(15 * time.Minute)
	u.LockedUntil = &future

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	var lockErr domain.ErrAccountLocked
	assert.ErrorAs(t, err, &lockErr)
}

func TestAuthService_Login_SoftDeletedUser(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")
	deletedAt := time.Now().Add(-1 * time.Hour)
	u.DeletedAt = &deletedAt

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestAuthService_Login_AccountLockout(t *testing.T) {
	userID := uuid.New()
	var lockedAt time.Time

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			u := validUser(userID, "test@example.com", "correct")
			u.FailedLoginCount = 4 // One more attempt will lock
			return u, nil
		},
		IncrementFailedLoginFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
		GetByIDFunc: func(ctx context.Context, id uuid.UUID) (domain.User, error) {
			u := validUser(userID, "test@example.com", "correct")
			u.FailedLoginCount = 5
			return u, nil
		},
		SetLockFunc: func(ctx context.Context, id uuid.UUID, until time.Time) error {
			lockedAt = until
			return nil
		},
	}

	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), newTestConfig())
	_, err := svc.Login(context.Background(), "test@example.com", "wrong", domain.ClientMeta{})

	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	assert.False(t, lockedAt.IsZero(), "SetLock should have been called")
}

func TestAuthService_Login_EmailVerificationRequired(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")
	u.EmailVerified = false

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}

	cfg := newTestConfig()
	cfg.RequireEmailVerified = true
	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), cfg)
	_, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	var verifyErr domain.ErrEmailNotVerified
	assert.ErrorAs(t, err, &verifyErr)
}

// --- MFA Tests ---

func TestAuthService_Login_MFAChallenge(t *testing.T) {
	userID := uuid.New()
	u := validUser(userID, "test@example.com", "password")

	users := &mocks.UserRepoMock{
		GetByEmailFunc: func(ctx context.Context, e string) (domain.User, error) {
			return u, nil
		},
	}
	mfaRepo := &mocks.MFARepoMock{
		GetMFAFunc: func(ctx context.Context, id uuid.UUID) (domain.MFAConfig, bool, error) {
			return domain.MFAConfig{UserID: id, Enabled: true}, true, nil
		},
	}

	svc := auth.NewAuthService(users, nil, mfaRepo, nil, nil, newTestJWTManager(), newTestConfig())
	result, err := svc.Login(context.Background(), "test@example.com", "password", domain.ClientMeta{})

	require.NoError(t, err)
	assert.True(t, result.MFARequired)
	assert.NotEmpty(t, result.MFAToken)
	assert.Empty(t, result.AccessToken)
	assert.Empty(t, result.RefreshToken)
}

// --- Refresh Tests ---

func TestAuthService_Refresh_Success(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	jwtm := newTestJWTManager()
	refreshTok, _, _ := jwtm.NewRefreshToken(userID, 0, sessionID, 720*time.Hour)
	rtHash := auth.HashToken(refreshTok)

	users := &mocks.UserRepoMock{
		GetByIDFunc: func(ctx context.Context, id uuid.UUID) (domain.User, error) {
			return validUser(userID, "test@example.com", "password"), nil
		},
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{
		GetByHashFunc: func(ctx context.Context, hash string) (domain.RefreshToken, error) {
			return domain.RefreshToken{
				ID:        uuid.New(),
				UserID:    userID,
				SessionID: sessionID,
				TokenHash: hash,
				ExpiresAt: time.Now().Add(720 * time.Hour),
			}, nil
		},
		RotateFunc: func(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, device string) (domain.RotateResult, error) {
			return domain.RotateResult{
				UserID:    userID,
				SessionID: sessionID,
			}, nil
		},
	}

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, nil, jwtm, newTestConfig())
	result, err := svc.Refresh(context.Background(), refreshTok, domain.ClientMeta{IP: "127.0.0.1"}, "")

	require.NoError(t, err)
	assert.Equal(t, userID, result.UserID)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Len(t, refreshRepo.RotateCalls, 1)
	assert.Equal(t, rtHash, refreshRepo.RotateCalls[0].OldHash)
}

func TestAuthService_Refresh_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	jwtm := newTestJWTManager()
	refreshTok, _, _ := jwtm.NewRefreshToken(userID, 0, sessionID, -1*time.Hour) // expired

	refreshRepo := &mocks.RefreshTokenRepoMock{
		GetByHashFunc: func(ctx context.Context, hash string) (domain.RefreshToken, error) {
			return domain.RefreshToken{
				UserID:    userID,
				SessionID: sessionID,
				ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
			}, nil
		},
	}

	svc := auth.NewAuthService(nil, refreshRepo, nil, nil, nil, jwtm, newTestConfig())
	_, err := svc.Refresh(context.Background(), refreshTok, domain.ClientMeta{}, "")

	assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
}

func TestAuthService_Refresh_RevokedToken(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	jwtm := newTestJWTManager()
	refreshTok, _, _ := jwtm.NewRefreshToken(userID, 0, sessionID, 720*time.Hour)

	revokedAt := time.Now().Add(-1 * time.Hour)
	refreshRepo := &mocks.RefreshTokenRepoMock{
		GetByHashFunc: func(ctx context.Context, hash string) (domain.RefreshToken, error) {
			return domain.RefreshToken{
				UserID:    userID,
				SessionID: sessionID,
				ExpiresAt: time.Now().Add(720 * time.Hour),
				RevokedAt: &revokedAt,
			}, nil
		},
	}

	svc := auth.NewAuthService(nil, refreshRepo, nil, nil, nil, jwtm, newTestConfig())
	_, err := svc.Refresh(context.Background(), refreshTok, domain.ClientMeta{}, "")

	assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
}

func TestAuthService_Refresh_ReplayDetection(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	jwtm := newTestJWTManager()
	refreshTok, _, _ := jwtm.NewRefreshToken(userID, 0, sessionID, 720*time.Hour)
	rtHash := auth.HashToken(refreshTok)

	users := &mocks.UserRepoMock{
		GetByIDFunc: func(ctx context.Context, id uuid.UUID) (domain.User, error) {
			return validUser(userID, "test@example.com", "password"), nil
		},
		IncrementTokenVersionFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{
		GetByHashFunc: func(ctx context.Context, hash string) (domain.RefreshToken, error) {
			return domain.RefreshToken{
				UserID:    userID,
				SessionID: sessionID,
				ExpiresAt: time.Now().Add(720 * time.Hour),
			}, nil
		},
		RotateFunc: func(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, device string) (domain.RotateResult, error) {
			assert.Equal(t, rtHash, oldHash)
			return domain.RotateResult{
				UserID:         userID,
				SessionID:      sessionID,
				ReplayDetected: true,
			}, nil
		},
	}

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, nil, jwtm, newTestConfig())
	_, err := svc.Refresh(context.Background(), refreshTok, domain.ClientMeta{}, "")

	assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
	// Verify token version was incremented (replay response)
	assert.Len(t, users.IncrementTokenVersionCalls, 1)
}

func TestAuthService_Refresh_TokenVersionMismatch(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	jwtm := newTestJWTManager()
	refreshTok, _, _ := jwtm.NewRefreshToken(userID, 0, sessionID, 720*time.Hour)

	users := &mocks.UserRepoMock{
		GetByIDFunc: func(ctx context.Context, id uuid.UUID) (domain.User, error) {
			u := validUser(userID, "test@example.com", "password")
			u.TokenVersion = 1 // mismatch with token's version 0
			return u, nil
		},
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{
		GetByHashFunc: func(ctx context.Context, hash string) (domain.RefreshToken, error) {
			return domain.RefreshToken{
				UserID:    userID,
				SessionID: sessionID,
				ExpiresAt: time.Now().Add(720 * time.Hour),
			}, nil
		},
	}

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, nil, jwtm, newTestConfig())
	_, err := svc.Refresh(context.Background(), refreshTok, domain.ClientMeta{}, "")

	assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
}

// --- Logout Tests ---

func TestAuthService_Logout_Success(t *testing.T) {
	userID := uuid.New()
	jti := uuid.New().String()
	accessExp := time.Now().Add(15 * time.Minute)

	users := &mocks.UserRepoMock{
		IncrementTokenVersionFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}
	denylist := mocks.NewDenylistMock()

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, denylist, newTestJWTManager(), newTestConfig())
	err := svc.Logout(context.Background(), userID, jti, accessExp)

	require.NoError(t, err)
	assert.Len(t, users.IncrementTokenVersionCalls, 1)
	assert.Len(t, refreshRepo.RevokeAllForUserCalls, 1)
	assert.True(t, denylist.IsDeniedJTI(jti))
}

func TestAuthService_Logout_ExpiredAccessToken_NotDenylisted(t *testing.T) {
	userID := uuid.New()
	jti := uuid.New().String()
	accessExp := time.Now().Add(-1 * time.Minute) // already expired

	users := &mocks.UserRepoMock{
		IncrementTokenVersionFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}
	refreshRepo := &mocks.RefreshTokenRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, id uuid.UUID) error { return nil },
	}
	denylist := mocks.NewDenylistMock()

	svc := auth.NewAuthService(users, refreshRepo, nil, nil, denylist, newTestJWTManager(), newTestConfig())
	err := svc.Logout(context.Background(), userID, jti, accessExp)

	require.NoError(t, err)
	assert.False(t, denylist.IsDeniedJTI(jti), "expired token should not be denylisted")
}

// --- Config Tests ---

func TestAuthService_DefaultConfig(t *testing.T) {
	cfg := auth.DefaultConfig()
	assert.Equal(t, 15*time.Minute, cfg.AccessTokenTTL)
	assert.Equal(t, 720*time.Hour, cfg.RefreshTokenTTL)
	assert.Equal(t, "authkit", cfg.Issuer)
	assert.Equal(t, 5, cfg.MaxFailedLoginAttempts)
	assert.Equal(t, 15*time.Minute, cfg.AccountLockDuration)
}

func TestAuthService_ZeroConfigDefaults(t *testing.T) {
	users := &mocks.UserRepoMock{}
	svc := auth.NewAuthService(users, nil, nil, nil, nil, newTestJWTManager(), auth.Config{})

	// Should not panic with zero config
	require.NotNil(t, svc)
}
