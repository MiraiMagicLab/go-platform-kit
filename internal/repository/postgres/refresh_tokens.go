package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
		select id, user_id, token_hash, expires_at, revoked_at, revoked_reason, created_at
		from refresh_tokens
		where token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.RevokedReason, &t.CreatedAt)
	return t, err
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update refresh_tokens
		set revoked_at = now(),
		    revoked_reason = 'rotated',
		    replaced_by = $2
		where id = $1 and revoked_at is null
	`, refreshTokenID, replacedBy)
	return err
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update refresh_tokens
		set revoked_at = now(),
		    revoked_reason = 'logout_all'
		where user_id = $1 and revoked_at is null
	`, userID)
	return err
}

func (r *RefreshTokenRepo) Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newExpiresAt time.Time) (repository.RotateResult, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return repository.RotateResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldID, userID uuid.UUID
	var expiresAt time.Time
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		select id, user_id, expires_at, revoked_at
		from refresh_tokens
		where token_hash = $1
		for update
	`, oldTokenHash).Scan(&oldID, &userID, &expiresAt, &revokedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return repository.RotateResult{Invalid: true}, nil
		}
		return repository.RotateResult{}, err
	}

	if revokedAt != nil || time.Now().After(expiresAt) {
		// Replay/expired token use attempt. Hard revoke all active refresh tokens for this user.
		if _, err := tx.Exec(ctx, `
			update refresh_tokens
			set revoked_at = now(),
			    revoked_reason = 'replay_detected'
			where user_id = $1 and revoked_at is null
		`, userID); err != nil {
			return repository.RotateResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return repository.RotateResult{}, err
		}
		return repository.RotateResult{
			UserID:         userID,
			Invalid:        true,
			ReplayDetected: true,
		}, nil
	}

	var newID uuid.UUID
	err = tx.QueryRow(ctx, `
		insert into refresh_tokens (user_id, token_hash, expires_at)
		values ($1, $2, $3)
		returning id
	`, userID, newTokenHash, newExpiresAt).Scan(&newID)
	if err != nil {
		return repository.RotateResult{}, err
	}

	if _, err := tx.Exec(ctx, `
		update refresh_tokens
		set revoked_at = now(),
		    revoked_reason = 'rotated',
		    replaced_by = $2
		where id = $1 and revoked_at is null
	`, oldID, newID); err != nil {
		return repository.RotateResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return repository.RotateResult{}, err
	}
	return repository.RotateResult{
		UserID:            userID,
		NewRefreshTokenID: &newID,
	}, nil
}

func (r *RefreshTokenRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		delete from refresh_tokens
		where expires_at < $1
		   or (revoked_at is not null and revoked_at < $1 - interval '30 days')
	`, now)
	return err
}
