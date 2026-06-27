// JWT types and helpers re-exported from auth/internal/security/jwt.
package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"

type (
	// TokenType distinguishes access, refresh, and MFA step-up tokens.
	TokenType = jwt.TokenType
	// Claims holds validated JWT payload fields.
	Claims = jwt.Claims
	// JWTManager signs and verifies auth tokens.
	JWTManager = jwt.Manager
)

const (
	// TokenTypeAccess is a short-lived API access token.
	TokenTypeAccess = jwt.TokenTypeAccess
	// TokenTypeRefresh is a long-lived session refresh token.
	TokenTypeRefresh = jwt.TokenTypeRefresh
	// TokenTypeMFA is a temporary token issued between password and 2FA verification.
	TokenTypeMFA = jwt.TokenTypeMFA
)

// NewJWTManager constructs a JWT manager from HMAC secrets and issuer name.
func NewJWTManager(accessSecret, refreshSecret, issuer string) *JWTManager {
	return jwt.NewManager(accessSecret, refreshSecret, issuer)
}

// IsExpired reports whether err indicates an expired JWT.
func IsExpired(err error) bool { return jwt.IsExpired(err) }
