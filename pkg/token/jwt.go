package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeMFA     TokenType = "mfa"
)

type Claims struct {
	TokenType    TokenType `json:"typ"`
	TokenVersion int       `json:"tv"`
	// SessionID (sid) groups refresh chains for a single logical login (device). Omitted for legacy tokens.
	SessionID string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	accessSecret  []byte
	refreshSecret []byte
	issuer        string
}

func NewJWTManager(accessSecret, refreshSecret, issuer string) *JWTManager {
	return &JWTManager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		issuer:        issuer,
	}
}

func (m *JWTManager) NewAccessToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeAccess, userID, tokenVersion, sessionID, ttl)
}

func (m *JWTManager) NewRefreshToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeRefresh, userID, tokenVersion, sessionID, ttl)
}

func (m *JWTManager) NewMFAToken(userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, string, error) {
	// MFA token is short-lived and is only used to complete 2FA challenge.
	// It is signed with access secret.
	return m.newToken(TokenTypeMFA, userID, tokenVersion, uuid.Nil, ttl)
}

func (m *JWTManager) ParseAccess(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, TokenTypeAccess)
}

func (m *JWTManager) ParseRefresh(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.refreshSecret, TokenTypeRefresh)
}

func (m *JWTManager) ParseMFA(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, TokenTypeMFA)
}

func (m *JWTManager) newToken(tt TokenType, userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (tokenStr string, jti string, err error) {
	now := time.Now()
	jtiUUID := uuid.New().String()

	claims := Claims{
		TokenType:    tt,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ID:        jtiUUID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	if sessionID != uuid.Nil {
		claims.SessionID = sessionID.String()
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	var secret []byte
	if tt == TokenTypeAccess {
		secret = m.accessSecret
	} else {
		secret = m.refreshSecret
	}

	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", "", err
	}

	return signed, jtiUUID, nil
}

func (m *JWTManager) parse(tokenStr string, secret []byte, expectedType TokenType) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithLeeway(10*time.Second))
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.TokenType != expectedType {
		return nil, errors.New("invalid token type")
	}
	return claims, nil
}

func IsExpired(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
