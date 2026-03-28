package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EmailTokenRepo struct {
	db *pgxpool.Pool
}

func NewEmailTokenRepo(db *pgxpool.Pool) *EmailTokenRepo { return &EmailTokenRepo{db: db} }

func (r *EmailTokenRepo) Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		insert into email_action_tokens (user_id, action_type, token_hash, expires_at)
		values ($1, $2, $3, $4)
	`, userID, actionType, tokenHash, expiresAt)
	return err
}

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
		select id, user_id, expires_at, used_at
		from email_action_tokens
		where action_type = $1 and token_hash = $2
		for update
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
	if _, err := tx.Exec(ctx, `update email_action_tokens set used_at = $2 where id = $1 and used_at is null`, id, now); err != nil {
		return uuid.Nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, err
	}
	return userID, true, nil
}

func (r *EmailTokenRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		delete from email_action_tokens
		where expires_at < $1
		   or (used_at is not null and used_at < $1 - interval '30 days')
	`, now)
	return err
}

