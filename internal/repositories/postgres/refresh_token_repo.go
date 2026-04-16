package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
	`, userID, tokenHash, expiresAt).Scan(&id)
	return id, err
}

func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (RefreshTokenDTO, error) {
	var t RefreshTokenDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, revoked_at, revoked_reason, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.RevokedReason, &t.CreatedAt)
	return t, err
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'rotated',
		    replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`, refreshTokenID, replacedBy)
	return err
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'logout_all'
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

func (r *RefreshTokenRepo) Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newExpiresAt time.Time) (RotateResult, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RotateResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldID, userID uuid.UUID
	var expiresAt time.Time
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, expires_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, oldTokenHash).Scan(&oldID, &userID, &expiresAt, &revokedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return RotateResult{Invalid: true}, nil
		}
		return RotateResult{}, err
	}

	if revokedAt != nil || time.Now().After(expiresAt) {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET revoked_at = NOW(),
			    revoked_reason = 'replay_detected'
			WHERE user_id = $1 AND revoked_at IS NULL
		`, userID); err != nil {
			return RotateResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RotateResult{}, err
		}
		return RotateResult{
			UserID:         userID,
			Invalid:        true,
			ReplayDetected: true,
		}, nil
	}

	var newID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
	`, userID, newTokenHash, newExpiresAt).Scan(&newID)
	if err != nil {
		return RotateResult{}, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'rotated',
		    replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`, oldID, newID); err != nil {
		return RotateResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return RotateResult{}, err
	}
	return RotateResult{
		UserID:            userID,
		NewRefreshTokenID: &newID,
	}, nil
}

func (r *RefreshTokenRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM refresh_tokens
		WHERE expires_at < $1
		   OR (revoked_at IS NOT NULL AND revoked_at < $1 - INTERVAL '30 days')
	`, now)
	return err
}
