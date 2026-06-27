package testmem

import (
	"testing"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"
	login "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/login"
)

const (
	TestAccessSecret  = "access-secret-key-32bytes-min!!"
	TestRefreshSecret = "refresh-secret-key-32bytes-min!"
)

// JWTManager returns a test JWT manager.
func JWTManager() *jwt.Manager {
	return jwt.NewManager(TestAccessSecret, TestRefreshSecret, "test")
}

// LoginConfig returns a test login service config.
func LoginConfig() login.Config {
	return login.Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: time.Hour,
	}
}

// NewLoginService wires an AuthService with optional MFA repo and verifier.
func NewLoginService(t *testing.T, users *Users, sessions *Sessions, refresh *RefreshTokens, mfaRepo *MFA, mfaVerifier login.MFAVerifier) *login.AuthService {
	t.Helper()
	var mfa ports.MFARepository
	if mfaRepo != nil {
		mfa = mfaRepo
	}
	return login.NewAuthService(users, sessions, refresh, mfa, mfaVerifier, nil, JWTManager(), LoginConfig())
}
