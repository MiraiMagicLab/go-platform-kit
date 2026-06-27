package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IdentityRepo provides PostgreSQL-backed persistence for external identity links (OAuth providers).
type IdentityRepo struct {
	db *pgxpool.Pool
}

// NewIdentityRepo returns an IdentityRepo backed by the given connection pool.
func NewIdentityRepo(db *pgxpool.Pool) *IdentityRepo {
	return &IdentityRepo{db: db}
}

// FindUserIDByProvider returns the user ID linked to the given external provider and subject.
// If no link exists, it returns false with a nil error.
func (r *IdentityRepo) FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error) {
	var userID uuid.UUID
	err := r.db.QueryRow(ctx, `
		SELECT user_id
		FROM user_identities
		WHERE provider = $1 AND provider_subject = $2
	`, provider, providerSubject).Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, err
	}
	return userID, true, nil
}

// LinkIdentity associates an external provider identity with a user.
// It is a no-op if the provider/subject pair is already linked.
func (r *IdentityRepo) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_identities (user_id, provider, provider_subject, email)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		ON CONFLICT (provider, provider_subject) DO NOTHING
	`, userID, provider, providerSubject, email)
	return err
}
