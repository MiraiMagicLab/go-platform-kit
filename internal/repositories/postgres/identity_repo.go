package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IdentityRepo struct {
	db *pgxpool.Pool
}

func NewIdentityRepo(db *pgxpool.Pool) *IdentityRepo {
	return &IdentityRepo{db: db}
}

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

func (r *IdentityRepo) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_identities (user_id, provider, provider_subject, email)
		VALUES ($1, $2, $3, NULLIF($4, ''))
		ON CONFLICT (provider, provider_subject) DO NOTHING
	`, userID, provider, providerSubject, email)
	return err
}

