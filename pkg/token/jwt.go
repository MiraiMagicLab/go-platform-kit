// Package token provides JWT creation and parsing for access, refresh, and MFA tokens.
// Tokens are signed using HS256 with separate secrets for access and refresh tokens.
package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType identifies the purpose of a JWT (access, refresh, or MFA challenge).
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeMFA     TokenType = "mfa"
)

// Claims extends jwt.RegisteredClaims with application-specific fields for token
// type, version tracking, and optional session ID.
type Claims struct {
	TokenType    TokenType `json:"typ"`
	TokenVersion int       `json:"tv"`
	// SessionID (sid) groups refresh chains for a single logical login (device). Omitted for legacy tokens.
	SessionID string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager creates and validates JWT tokens using separate HS256 secrets for
// access and refresh tokens.
type JWTManager struct {
	accessSecret  []byte
	refreshSecret []byte
	issuer        string
}

// NewJWTManager creates a JWTManager with the given HS256 signing secrets and issuer.
// accessSecret is used to sign access and MFA tokens; refreshSecret is used for refresh tokens.
func NewJWTManager(accessSecret, refreshSecret, issuer string) *JWTManager {
	return &JWTManager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		issuer:        issuer,
	}
}

// NewAccessToken creates a short-lived access JWT for the given user. It returns
// the signed token string, its jti (unique identifier), and any signing error.
func (m *JWTManager) NewAccessToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeAccess, userID, tokenVersion, sessionID, ttl)
}

// NewRefreshToken creates a long-lived refresh JWT for the given user. The token
// is signed with the refresh secret and includes the session ID for session-scoped
// token management.
func (m *JWTManager) NewRefreshToken(userID uuid.UUID, tokenVersion int, sessionID uuid.UUID, ttl time.Duration) (string, string, error) {
	return m.newToken(TokenTypeRefresh, userID, tokenVersion, sessionID, ttl)
}

// NewMFAToken creates a short-lived MFA challenge JWT used to complete two-factor
// authentication. It is signed with the access secret and does not carry a session ID.
func (m *JWTManager) NewMFAToken(userID uuid.UUID, tokenVersion int, ttl time.Duration) (string, string, error) {
	// MFA token is short-lived and is only used to complete 2FA challenge.
	// It is signed with access secret.
	return m.newToken(TokenTypeMFA, userID, tokenVersion, uuid.Nil, ttl)
}

// ParseAccess validates and parses an access token string. It returns the parsed
// claims or an error if the token is expired, malformed, or has a mismatched type.
func (m *JWTManager) ParseAccess(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, TokenTypeAccess)
}

// ParseRefresh validates and parses a refresh token string using the refresh secret.
func (m *JWTManager) ParseRefresh(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.refreshSecret, TokenTypeRefresh)
}

// ParseMFA validates and parses an MFA challenge token using the access secret.
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

// IsExpired reports whether err indicates a JWT expiration error.
func IsExpired(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
