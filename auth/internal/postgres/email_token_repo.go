package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

var _ ports.EmailTokenRepository = (*EmailTokenRepo)(nil)

// EmailTokenRepo provides PostgreSQL-backed persistence for single-use email action tokens
// (e.g. email verification, password reset).
type EmailTokenRepo struct {
	db *pgxpool.Pool
}

// NewEmailTokenRepo returns an EmailTokenRepo backed by the given connection pool.
func NewEmailTokenRepo(db *pgxpool.Pool) *EmailTokenRepo { return &EmailTokenRepo{db: db} }

// Create inserts a new email action token.
func (r *EmailTokenRepo) Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO email_action_tokens (user_id, action_type, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, actionType, tokenHash, expiresAt)
	return err
}

// Consume atomically validates and marks a single-use email action token as consumed within a transaction.
// It returns the associated user ID and true if the token was valid and consumed,
// or uuid.Nil and false if the token was not found, already used, or expired.
func (r *EmailTokenRepo) Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id, userID uuid.UUID
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at
		FROM email_action_tokens
		WHERE action_type = $1 AND token_hash = $2
		FOR UPDATE
	`, actionType, tokenHash).Scan(&id, &userID, &expiresAt, &usedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, err
	}
	if usedAt != nil || now.After(expiresAt) {
		return uuid.Nil, false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE email_action_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, id, now); err != nil {
		return uuid.Nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, err
	}
	return userID, true, nil
}

// Cleanup deletes expired tokens and tokens consumed more than 30 days ago.
func (r *EmailTokenRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM email_action_tokens
		WHERE expires_at < $1
		   OR (used_at IS NOT NULL AND used_at < $1 - INTERVAL '30 days')
	`, now)
	return err
}
