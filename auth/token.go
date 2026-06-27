package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/jwt"

type (
	TokenType  = jwt.TokenType
	Claims     = jwt.Claims
	JWTManager = jwt.Manager
)

const (
	TokenTypeAccess  = jwt.TokenTypeAccess
	TokenTypeRefresh = jwt.TokenTypeRefresh
	TokenTypeMFA     = jwt.TokenTypeMFA
)

func NewJWTManager(accessSecret, refreshSecret, issuer string) *JWTManager {
	return jwt.NewManager(accessSecret, refreshSecret, issuer)
}

func IsExpired(err error) bool { return jwt.IsExpired(err) }
