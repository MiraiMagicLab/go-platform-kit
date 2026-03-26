package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tienh/authsvc/internal/repository"
)

type RefreshTokenRepo struct {
	db *pgxpool.Pool
}

func NewRefreshTokenRepo(db *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

func (r *RefreshTokenRepo) Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		insert into refresh_tokens (user_id, token_hash, expires_at)
		values ($1, $2, $3)
		returning id
	`, userID, tokenHash, expiresAt).Scan(&id)
	return id, err
}

func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (repository.RefreshTokenDTO, error) {
	var t repository.RefreshTokenDTO
	err := r.db.QueryRow(ctx, `
		select id, user_id, token_hash, expires_at, revoked_at, created_at
		from refresh_tokens
		where token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt)
	return t, err
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update refresh_tokens
		set revoked_at = now(),
		    replaced_by = $2
		where id = $1 and revoked_at is null
	`, refreshTokenID, replacedBy)
	return err
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update refresh_tokens
		set revoked_at = now()
		where user_id = $1 and revoked_at is null
	`, userID)
	return err
}
