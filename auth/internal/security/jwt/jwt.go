package jwt

import (
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
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
	SessionID    string    `json:"sid,omitempty"`
	jwtlib.RegisteredClaims
}

type Manager struct {
	accessSecret  []byte
	refreshSecret []byte
	issuer        string
}

func NewManager(accessSecret, refreshSecret, issuer string) *Manager {
	return &Manager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		issuer:        issuer,
	}
}

func (m *Manager) NewAccessToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeAccess, userID, tokenVersion, sessionID, ttl)
}

func (m *Manager) NewRefreshToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeRefresh, userID, tokenVersion, sessionID, ttl)
}

func (m *Manager) NewMFAToken(userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeMFA, userID, tokenVersion, uuid.Nil, ttl)
}

func (m *Manager) ParseAccess(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, TokenTypeAccess)
}

func (m *Manager) ParseRefresh(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.refreshSecret, TokenTypeRefresh)
}

func (m *Manager) ParseMFA(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, TokenTypeMFA)
}

func (m *Manager) newToken(tt TokenType, userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (tokenStr string, jti string, err error) {
	now := time.Now()
	jtiUUID := uuid.New().String()

	claims := Claims{
		TokenType:    tt,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			ID:        jtiUUID,
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
		},
	}
	if sessionID != uuid.Nil {
		claims.SessionID = sessionID.String()
	}

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)

	var secret []byte
	if tt == TokenTypeAccess || tt == TokenTypeMFA {
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

func (m *Manager) parse(tokenStr string, secret []byte, expectedType TokenType) (*Claims, error) {
	parsed, err := jwtlib.ParseWithClaims(tokenStr, &Claims{}, func(token *jwtlib.Token) (interface{}, error) {
		if token.Method.Alg() != jwtlib.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwtlib.WithLeeway(10*time.Second))
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
	return errors.Is(err, jwtlib.ErrTokenExpired)
}
