//go:build integration

package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/postgres"
	platformpg "github.com/MiraiMagicLab/go-platform-kit/platform/postgres"
)

func openPool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	pg, err := platformpg.Open(ctx, platformpg.Config{URL: url})
	require.NoError(t, err)
	ensureSchema(t, ctx, pg)
	return pg, func() { pg.Close() }
}

func ensureSchema(t *testing.T, ctx context.Context, pg *pgxpool.Pool) {
	t.Helper()
	var exists bool
	require.NoError(t, pg.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'users'
		)
	`).Scan(&exists))
	if exists {
		return
	}
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	b, err := os.ReadFile(filepath.Join(root, "migrations", "0001_baseline.up.sql"))
	require.NoError(t, err)
	_, err = pg.Exec(ctx, string(b))
	require.NoError(t, err)
}

func TestUserRepoCreateAndGet(t *testing.T) {
	pg, cleanup := openPool(t)
	defer cleanup()
	repo := postgres.NewUserRepo(pg)
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	email := "pg-user-" + uuid.NewString() + "@example.com"
	id, err := repo.Create(ctx, email, string(hash))
	require.NoError(t, err)

	u, err := repo.GetByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, id, u.ID)
	require.True(t, u.PasswordLoginEnabled)
}

func TestUserRepoCreateOAuthUser(t *testing.T) {
	pg, cleanup := openPool(t)
	defer cleanup()
	repo := postgres.NewUserRepo(pg)
	ctx := context.Background()

	email := "oauth-" + uuid.NewString() + "@example.com"
	id, err := repo.CreateOAuthUser(ctx, email, "hash")
	require.NoError(t, err)

	u, err := repo.GetByID(ctx, id)
	require.NoError(t, err)
	require.False(t, u.PasswordLoginEnabled)
}

func TestIdentityRepoLinkAndFind(t *testing.T) {
	pg, cleanup := openPool(t)
	defer cleanup()
	users := postgres.NewUserRepo(pg)
	identities := postgres.NewIdentityRepo(pg)
	ctx := context.Background()

	email := "identity-" + uuid.NewString() + "@example.com"
	userID, err := users.CreateOAuthUser(ctx, email, "hash")
	require.NoError(t, err)

	subject := "google-sub-" + uuid.NewString()
	require.NoError(t, identities.LinkIdentity(ctx, userID, "google", subject, email))

	found, ok, err := identities.FindUserIDByProvider(ctx, "google", subject)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, userID, found)
}
