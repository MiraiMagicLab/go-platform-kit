package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/MicahParks/keyfunc"

	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

// TeamClaims is the control-plane-issued JWT used for admin SSO (TeamToken).
// Subject is expected to be the user UUID in the host app DB.
type TeamClaims struct {
	jwt.RegisteredClaims
	WorkspaceID string   `json:"workspace_id,omitempty"`
	AppID       string   `json:"app_id,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type TeamTokenVerifier struct {
	issuer string
	aud    string
	jwks   *keyfunc.JWKS
}

func NewTeamTokenVerifier(jwksURL, issuer, aud string) (*TeamTokenVerifier, error) {
	if jwksURL == "" || issuer == "" || aud == "" {
		return nil, errors.New("jwksURL/issuer/aud are required")
	}

	j, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval:  time.Hour,
		RefreshTimeout:   5 * time.Second,
		RefreshRateLimit: 10 * time.Second,
		RefreshErrorHandler: func(err error) {
			// keep silent; middleware will fail token verification if keys are unavailable
		},
	})
	if err != nil {
		return nil, err
	}
	return &TeamTokenVerifier{issuer: issuer, aud: aud, jwks: j}, nil
}

func (v *TeamTokenVerifier) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		raw := strings.TrimSpace(authz[len("Bearer "):])

		claims := &TeamClaims{}
		tok, err := jwt.ParseWithClaims(raw, claims, v.jwks.Keyfunc)
		if err != nil || tok == nil || !tok.Valid {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthInvalidToken, nil)
			c.Abort()
			return
		}

		if claims.Issuer != v.issuer {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}
		if !audContains(claims.Audience, v.aud) {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		subjectUUID, err := uuid.Parse(claims.Subject)
		if err != nil {
			response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
			c.Abort()
			return
		}

		// go-auth-lib's RBAC middleware reads `user_id` from Gin context.
		c.Set("user_id", subjectUUID)
		// Keep extra debug/compat fields (optional use by host apps).
		c.Set("controlplane_subject", claims.Subject)
		c.Set("controlplane_permissions", claims.Permissions)
		c.Next()
	}
}

func audContains(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
