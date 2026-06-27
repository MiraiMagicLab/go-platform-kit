//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
	"github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func openTestAuth(t *testing.T) (context.Context, *auth.Auth, func()) {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}

	pg, err := postgres.Open(ctx, postgres.Config{URL: url})
	require.NoError(t, err)
	ensureBaselineSchema(t, ctx, pg)

	cfg := auth.DefaultConfig()
	cfg.JWTAccessSecret = "test-access-secret"
	cfg.JWTRefreshSecret = "test-refresh-secret"
	cfg.AccessTokenTTL = 15 * time.Minute
	cfg.RefreshTokenTTL = time.Hour

	a, err := auth.Open(ctx, auth.WithConfig(cfg), auth.WithPostgres(pg))
	require.NoError(t, err)
	require.NotNil(t, a)

	return ctx, a, func() { pg.Close() }
}

func ensureBaselineSchema(t *testing.T, ctx context.Context, pg *pgxpool.Pool) {
	t.Helper()
	var exists bool
	err := pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'users'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	if exists {
		return
	}

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	sqlPath := filepath.Join(root, "migrations", "0001_baseline.up.sql")
	b, err := os.ReadFile(sqlPath)
	require.NoError(t, err)
	_, err = pg.Exec(ctx, string(b))
	require.NoError(t, err)
}

func uniqueEmail(prefix string) string {
	return prefix + "-" + time.Now().Format("20060102150405.000") + "@example.com"
}

func TestAuthOpenAndRegister(t *testing.T) {
	ctx, a, cleanup := openTestAuth(t)
	defer cleanup()

	email := uniqueEmail("integration")
	id, err := a.Register(ctx, email, "password123")
	require.NoError(t, err)
	require.NotEqual(t, id.String(), "00000000-0000-0000-0000-000000000000")

	roles, err := a.ListUserRoles(ctx, id)
	require.NoError(t, err)
	require.Contains(t, roles, "user")
}

func TestAuthLoginAndLogoutCurrentSession(t *testing.T) {
	ctx, a, cleanup := openTestAuth(t)
	defer cleanup()

	email := uniqueEmail("login")
	password := "password123"
	_, err := a.Register(ctx, email, password)
	require.NoError(t, err)

	meta := auth.ClientMeta{IP: "127.0.0.1", UA: "integration-test"}
	res, err := a.Login(ctx, email, password, meta)
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
	require.False(t, res.MFARequired)

	userID, sessionID, jti, exp := parseAccessTokenClaims(t, res.AccessToken)
	require.Equal(t, res.UserID, userID)
	require.NotEqual(t, uuid.Nil, sessionID)

	err = a.Logout(ctx, userID, sessionID, jti, exp)
	require.NoError(t, err)

	refreshRes, err := a.Refresh(ctx, res.RefreshToken, meta, "")
	require.Error(t, err)
	require.Empty(t, refreshRes.AccessToken)
}

func TestAuthRefreshRotatesTokens(t *testing.T) {
	ctx, a, cleanup := openTestAuth(t)
	defer cleanup()

	email := uniqueEmail("refresh")
	password := "password123"
	_, err := a.Register(ctx, email, password)
	require.NoError(t, err)

	meta := auth.ClientMeta{IP: "127.0.0.1", UA: "integration-test"}
	res, err := a.Login(ctx, email, password, meta)
	require.NoError(t, err)

	rotated, err := a.Refresh(ctx, res.RefreshToken, meta, "")
	require.NoError(t, err)
	require.NotEmpty(t, rotated.AccessToken)
	require.NotEmpty(t, rotated.RefreshToken)
	require.NotEqual(t, res.RefreshToken, rotated.RefreshToken)

	_, err = a.Refresh(ctx, res.RefreshToken, meta, "")
	require.Error(t, err)
}

func TestAuthMFAFlow(t *testing.T) {
	ctx, a, cleanup := openTestAuth(t)
	defer cleanup()

	email := uniqueEmail("mfa")
	password := "password123"
	userID, err := a.Register(ctx, email, password)
	require.NoError(t, err)

	setup, err := a.SetupMFA(ctx, userID, email)
	require.NoError(t, err)
	require.NotEmpty(t, setup.Secret)

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, a.EnableMFA(ctx, userID, code))

	meta := auth.ClientMeta{IP: "127.0.0.1", UA: "integration-test"}
	challenge, err := a.Login(ctx, email, password, meta)
	require.NoError(t, err)
	require.True(t, challenge.MFARequired)
	require.NotEmpty(t, challenge.MFAToken)

	code2, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	res, err := a.CompleteMFA(ctx, challenge.MFAToken, code2, meta)
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.NotEmpty(t, res.RefreshToken)
}

func TestAuthRBACPermissions(t *testing.T) {
	ctx, a, cleanup := openTestAuth(t)
	defer cleanup()

	email := uniqueEmail("rbac")
	userID, err := a.Register(ctx, email, "password123")
	require.NoError(t, err)

	roleID, err := a.CreateRole(ctx, "content-editor")
	require.NoError(t, err)
	permID, err := a.CreatePermission(ctx, "content.publish")
	require.NoError(t, err)
	require.NoError(t, a.AssignPermissionsToRole(ctx, roleID, []uuid.UUID{permID}))
	require.NoError(t, a.AssignRolesToUser(ctx, userID, []uuid.UUID{roleID}))

	perms, err := a.ListUserPermissions(ctx, userID)
	require.NoError(t, err)
	require.Contains(t, perms, "content.publish")
}

func parseAccessTokenClaims(t *testing.T, accessToken string) (userID, sessionID uuid.UUID, jti string, exp time.Time) {
	t.Helper()
	var claims struct {
		SID string `json:"sid"`
		jwtlib.RegisteredClaims
	}
	_, _, err := jwtlib.NewParser().ParseUnverified(accessToken, &claims)
	require.NoError(t, err)

	userID, err = uuid.Parse(claims.Subject)
	require.NoError(t, err)
	sessionID, err = uuid.Parse(claims.SID)
	require.NoError(t, err)
	jti = claims.ID
	require.NotNil(t, claims.ExpiresAt)
	exp = claims.ExpiresAt.Time
	return userID, sessionID, jti, exp
}
