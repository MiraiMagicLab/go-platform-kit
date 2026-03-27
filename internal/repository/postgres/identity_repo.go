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
		select user_id
		from user_identities
		where provider = $1 and provider_subject = $2
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
		insert into user_identities (user_id, provider, provider_subject, email)
		values ($1, $2, $3, nullif($4, ''))
		on conflict (provider, provider_subject) do nothing
	`, userID, provider, providerSubject, email)
	return err
}

