//go:build integration
// +build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/internal/auth"
	"github.com/MiraiMagicLab/go-platform-kit/internal/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/internal/rbac"
	"github.com/MiraiMagicLab/go-platform-kit/internal/session"
	"github.com/MiraiMagicLab/go-platform-kit/internal/storage/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/token"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://test:test@localhost:5432/goauthlib_test?sslmode=disable"
	}

	ctx := context.Background()
	var err error
	testPool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	defer testPool.Close()

	// Run migrations
	if err := runMigrations(ctx, testPool); err != nil {
		panic("failed to run migrations: " + err.Error())
	}

	os.Exit(m.Run())
}

func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Read and execute the schema file
	schema, err := os.ReadFile("../sql/schema.sql")
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, string(schema))
	return err
}

func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	// Use the shared pool but clean up after each test
	return testPool, func() {
		// Clean up test data
		ctx := context.Background()
		_, _ = testPool.Exec(ctx, "DELETE FROM users WHERE email LIKE '%@test.com'")
	}
}

func TestAuthFlow_Register_Login_Refresh_Logout(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create adapters
	repos := postgres.NewRepos(pool)
	userRepo := postgres.NewUserAdapter(repos.User)
	refreshRepo := postgres.NewRefreshTokenAdapter(repos.RefreshToken)

	// Create JWT manager
	jwtm := token.NewJWTManager("test-access-secret-32bytes-long!!", "test-refresh-secret-32bytes-long!", "test")

	// Create auth service
	authCfg := auth.Config{
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        720 * time.Hour,
		Issuer:                 "test",
		MaxFailedLoginAttempts: 5,
		AccountLockDuration:    15 * time.Minute,
	}
	authSvc := auth.NewAuthService(userRepo, refreshRepo, nil, nil, nil, jwtm, authCfg)

	// Step 1: Register
	email := "test_" + uuid.New().String() + "@test.com"
	password := "password123"
	userID, err := authSvc.Register(ctx, email, password)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, userID)

	// Step 2: Login
	loginResult, err := authSvc.Login(ctx, email, password, domain.ClientMeta{
		IP: "127.0.0.1",
		UA: "test-agent",
	})
	require.NoError(t, err)
	assert.Equal(t, userID, loginResult.UserID)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.RefreshToken)
	assert.False(t, loginResult.MFARequired)

	// Step 3: Refresh
	refreshResult, err := authSvc.Refresh(ctx, loginResult.RefreshToken, domain.ClientMeta{
		IP: "127.0.0.1",
		UA: "test-agent",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, userID, refreshResult.UserID)
	assert.NotEmpty(t, refreshResult.AccessToken)
	assert.NotEmpty(t, refreshResult.RefreshToken)

	// Step 4: Logout
	err = authSvc.Logout(ctx, userID, "test-jti", time.Now().Add(15*time.Minute))
	require.NoError(t, err)

	// Step 5: Verify old refresh token is invalid
	_, err = authSvc.Refresh(ctx, loginResult.RefreshToken, domain.ClientMeta{
		IP: "127.0.0.1",
		UA: "test-agent",
	}, "")
	assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
}

func TestAuthFlow_AccountLockout(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	repos := postgres.NewRepos(pool)
	userRepo := postgres.NewUserAdapter(repos.User)
	refreshRepo := postgres.NewRefreshTokenAdapter(repos.RefreshToken)

	jwtm := token.NewJWTManager("test-access-secret-32bytes-long!!", "test-refresh-secret-32bytes-long!", "test")

	authCfg := auth.Config{
		AccessTokenTTL:         15 * time.Minute,
		RefreshTokenTTL:        720 * time.Hour,
		Issuer:                 "test",
		MaxFailedLoginAttempts: 3,
		AccountLockDuration:    1 * time.Second, // Short for testing
	}
	authSvc := auth.NewAuthService(userRepo, refreshRepo, nil, nil, nil, jwtm, authCfg)

	// Register user
	email := "lockout_" + uuid.New().String() + "@test.com"
	_, err := authSvc.Register(ctx, email, "password123")
	require.NoError(t, err)

	// Fail login 3 times
	for i := 0; i < 3; i++ {
		_, err = authSvc.Login(ctx, email, "wrong-password", domain.ClientMeta{IP: "127.0.0.1"})
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	}

	// 4th attempt should be locked
	_, err = authSvc.Login(ctx, email, "password123", domain.ClientMeta{IP: "127.0.0.1"})
	var lockErr domain.ErrAccountLocked
	assert.ErrorAs(t, err, &lockErr)

	// Wait for lock to expire
	time.Sleep(2 * time.Second)

	// Should work now
	_, err = authSvc.Login(ctx, email, "password123", domain.ClientMeta{IP: "127.0.0.1"})
	assert.NoError(t, err)
}

func TestSessionService_List_Revoke(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	repos := postgres.NewRepos(pool)
	sessionRepo := postgres.NewSessionAdapter(repos.Sessions)
	refreshRepo := postgres.NewRefreshTokenAdapter(repos.RefreshToken)

	sessionSvc := session.NewSessionService(sessionRepo, refreshRepo, nil)

	// Create a test user first
	userRepo := postgres.NewUserAdapter(repos.User)
	email := "session_" + uuid.New().String() + "@test.com"
	userID, err := userRepo.Create(ctx, email, "hash")
	require.NoError(t, err)

	// Create sessions
	sess1, err := sessionSvc.CreateSession(ctx, userID, "Device 1", "127.0.0.1", "UA1")
	require.NoError(t, err)

	sess2, err := sessionSvc.CreateSession(ctx, userID, "Device 2", "127.0.0.2", "UA2")
	require.NoError(t, err)

	// List sessions
	sessions, err := sessionSvc.List(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// Revoke one session
	err = sessionSvc.RevokeSession(ctx, userID, sess2, uuid.Nil, "", time.Time{})
	require.NoError(t, err)

	// List again - should have 1
	sessions, err = sessionSvc.List(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, sess1, sessions[0].ID)
}

func TestRBACService_Create_Assign_Check(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	repos := postgres.NewRepos(pool)
	rbacRepo := postgres.NewRBACAdapter(repos.RBAC)
	userRepo := postgres.NewUserAdapter(repos.User)

	rbacSvc := rbac.NewRBACService(rbacRepo, nil, 30*time.Second)

	// Create test user
	email := "rbac_" + uuid.New().String() + "@test.com"
	userID, err := userRepo.Create(ctx, email, "hash")
	require.NoError(t, err)

	// Create role and permission
	roleID, err := rbacSvc.CreateRole(ctx, "test_role_"+uuid.New().String()[:8])
	require.NoError(t, err)

	permID, err := rbacSvc.CreatePermission(ctx, "test_perm_"+uuid.New().String()[:8])
	require.NoError(t, err)

	// Assign permission to role
	err = rbacSvc.AssignPermissionsToRole(ctx, roleID, []uuid.UUID{permID})
	require.NoError(t, err)

	// Assign role to user
	err = rbacSvc.AssignRolesToUser(ctx, userID, []uuid.UUID{roleID})
	require.NoError(t, err)

	// Check user permissions
	perms, err := rbacSvc.ListUserPermissions(ctx, userID)
	require.NoError(t, err)
	assert.NotEmpty(t, perms)

	// Check user roles
	roles, err := rbacSvc.ListUserRoles(ctx, userID)
	require.NoError(t, err)
	assert.NotEmpty(t, roles)
}

func TestMFAService_Setup_Enable_Verify(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	repos := postgres.NewRepos(pool)
	mfaRepo := postgres.NewMFAAdapter(repos.MFA)
	userRepo := postgres.NewUserAdapter(repos.User)

	mfaSvc := mfa.NewMFAService(mfaRepo, "test", nil)

	// Create test user
	email := "mfa_" + uuid.New().String() + "@test.com"
	userID, err := userRepo.Create(ctx, email, "hash")
	require.NoError(t, err)

	// Setup MFA
	setup, err := mfaSvc.SetupTOTP(ctx, userID, email)
	require.NoError(t, err)
	assert.NotEmpty(t, setup.Secret)
	assert.NotEmpty(t, setup.OTPAuthURL)
	assert.Len(t, setup.RecoveryCodes, 10)

	// Check MFA is not enabled yet
	enabled, err := mfaSvc.IsEnabled(ctx, userID)
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestDomainTypes_Methods(t *testing.T) {
	// Test User methods
	t.Run("User.IsBanned", func(t *testing.T) {
		u := domain.User{}

		// Not banned
		assert.False(t, u.IsBanned())

		// Banned in future
		future := time.Now().Add(24 * time.Hour)
		u.BannedUntil = &future
		assert.True(t, u.IsBanned())

		// Ban expired
		past := time.Now().Add(-1 * time.Hour)
		u.BannedUntil = &past
		assert.False(t, u.IsBanned())
	})

	t.Run("User.IsLocked", func(t *testing.T) {
		u := domain.User{}

		// Not locked
		assert.False(t, u.IsLocked())

		// Locked
		future := time.Now().Add(15 * time.Minute)
		u.LockedUntil = &future
		assert.True(t, u.IsLocked())
	})

	t.Run("User.IsDeleted", func(t *testing.T) {
		u := domain.User{}

		// Not deleted
		assert.False(t, u.IsDeleted())

		// Deleted
		now := time.Now()
		u.DeletedAt = &now
		assert.True(t, u.IsDeleted())
	})

	t.Run("RefreshToken.IsActive", func(t *testing.T) {
		rt := domain.RefreshToken{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.True(t, rt.IsActive())

		// Expired
		rt.ExpiresAt = time.Now().Add(-1 * time.Hour)
		assert.False(t, rt.IsActive())

		// Revoked
		rt.ExpiresAt = time.Now().Add(1 * time.Hour)
		now := time.Now()
		rt.RevokedAt = &now
		assert.False(t, rt.IsActive())
	})

	t.Run("Session.IsRevoked", func(t *testing.T) {
		s := domain.Session{}
		assert.False(t, s.IsRevoked())

		now := time.Now()
		s.RevokedAt = &now
		assert.True(t, s.IsRevoked())
	})
}
