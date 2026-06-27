package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// TeamClaims holds the claims from a control-plane TeamToken.
type TeamClaims struct {
	jwtlib.RegisteredClaims
	WorkspaceID  string   `json:"workspace_id"`
	AppID        string   `json:"app_id"`
	AppAccess    string   `json:"app_access"`
	Capabilities []string `json:"capabilities"`
}

// TeamAuth holds the parsed team auth data for a request.
type TeamAuth struct {
	ActorUserID  uuid.UUID
	WorkspaceID  uuid.UUID
	AppID        uuid.UUID
	AppAccess    string
	Capabilities []string
}

const ctxTeamAuthKey = "team_auth"

// TeamAuthFromCtx returns the TeamAuth from the Gin context.
func TeamAuthFromCtx(c *gin.Context) (*TeamAuth, bool) {
	v, ok := c.Get(ctxTeamAuthKey)
	if !ok {
		return nil, false
	}
	ta, ok := v.(*TeamAuth)
	return ta, ok
}

// TeamTokenVerifier verifies control-plane-issued TeamTokens using JWKS.
type TeamTokenVerifier struct {
	issuer string
	aud    string
	jwks   *keyfunc.JWKS
}

// NewTeamTokenVerifier creates a new TeamTokenVerifier.
func NewTeamTokenVerifier(jwksURL, issuer, aud string) (*TeamTokenVerifier, error) {
	j, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval:  time.Hour,
		RefreshTimeout:   5 * time.Second,
		RefreshRateLimit: 10 * time.Second,
		RefreshErrorHandler: func(err error) {
			// keep silent
		},
	})
	if err != nil {
		return nil, err
	}
	return &TeamTokenVerifier{issuer: issuer, aud: aud, jwks: j}, nil
}

// Middleware returns a Gin middleware that verifies TeamTokens.
func (v *TeamTokenVerifier) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			c.Abort()
			return
		}
		raw := strings.TrimSpace(authz[len("Bearer "):])

		claims := &TeamClaims{}
		tok, err := jwtlib.ParseWithClaims(raw, claims, v.jwks.Keyfunc,
			jwtlib.WithIssuer(v.issuer),
			jwtlib.WithAudience(v.aud),
		)
		if err != nil || tok == nil || !tok.Valid {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}

		subjectUUID, err := uuid.Parse(claims.Subject)
		if err != nil {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
			c.Abort()
			return
		}

		if claims.AppAccess != "read" && claims.AppAccess != "write" {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}
		if len(claims.Capabilities) == 0 {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}

		wsID, err := uuid.Parse(claims.WorkspaceID)
		if err != nil {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}
		appID, err := uuid.Parse(claims.AppID)
		if err != nil {
			httpx.Fail(c, http.StatusUnauthorized, httpx.CodeAuthTokenInvalid, nil)
			c.Abort()
			return
		}

		c.Set(ctxUserIDKey, subjectUUID)
		c.Set(ctxTeamAuthKey, &TeamAuth{
			ActorUserID:  subjectUUID,
			WorkspaceID:  wsID,
			AppID:        appID,
			AppAccess:    claims.AppAccess,
			Capabilities: claims.Capabilities,
		})
		c.Next()
	}
}

// RequireTeamAccess returns middleware that checks TeamToken app_access level.
func RequireTeamAccess(level string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ta, ok := TeamAuthFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusForbidden, httpx.CodeForbidden, nil)
			c.Abort()
			return
		}
		if !accessLevelGTE(ta.AppAccess, level) {
			httpx.FailCode(c, http.StatusForbidden, httpx.CodeForbidden, nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireTeamCapability returns middleware that checks TeamToken capability.
func RequireTeamCapability(capability string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ta, ok := TeamAuthFromCtx(c)
		if !ok {
			httpx.FailCode(c, http.StatusForbidden, httpx.CodeForbidden, nil)
			c.Abort()
			return
		}
		for _, cap := range ta.Capabilities {
			if cap == capability {
				c.Next()
				return
			}
		}
		httpx.FailCode(c, http.StatusForbidden, httpx.CodeForbidden, nil)
		c.Abort()
	}
}

func accessLevelGTE(actual, required string) bool {
	levels := map[string]int{"read": 1, "write": 2}
	return levels[actual] >= levels[required]
}
