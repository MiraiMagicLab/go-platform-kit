package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MFARepo struct {
	db *pgxpool.Pool
}

func NewMFARepo(db *pgxpool.Pool) *MFARepo { return &MFARepo{db: db} }

func (r *MFARepo) UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error {
	_, err := r.db.Exec(ctx, `
		insert into user_mfa (user_id, totp_secret, enabled)
		values ($1, $2, false)
		on conflict (user_id)
		do update set totp_secret = excluded.totp_secret, enabled = false, enabled_at = null
	`, userID, secret)
	return err
}

func (r *MFARepo) GetMFA(ctx context.Context, userID uuid.UUID) (MFADTO, bool, error) {
	var m MFADTO
	err := r.db.QueryRow(ctx, `
		select user_id, totp_secret, enabled, enabled_at, created_at
		from user_mfa
		where user_id = $1
	`, userID).Scan(&m.UserID, &m.TOTPSecret, &m.Enabled, &m.EnabledAt, &m.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return MFADTO{}, false, nil
		}
		return MFADTO{}, false, err
	}
	return m, true, nil
}

func (r *MFARepo) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update user_mfa
		set enabled = true, enabled_at = now()
		where user_id = $1
	`, userID)
	return err
}

func (r *MFARepo) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		delete from user_mfa where user_id = $1
	`, userID)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `delete from user_mfa_recovery_codes where user_id = $1`, userID)
	return err
}

func (r *MFARepo) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from user_mfa_recovery_codes where user_id = $1`, userID); err != nil {
		return err
	}

	batch := &pgx.Batch{}
	for _, h := range codeHashes {
		batch.Queue(`
			insert into user_mfa_recovery_codes (user_id, code_hash)
			values ($1, $2)
		`, userID, h)
	}
	br := tx.SendBatch(ctx, batch)
	for range codeHashes {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	_ = br.Close()

	return tx.Commit(ctx)
}

func (r *MFARepo) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		select id
		from user_mfa_recovery_codes
		where user_id = $1 and code_hash = $2 and used_at is null
		limit 1
	`, userID, codeHash).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	now := time.Now()
	ct, err := r.db.Exec(ctx, `
		update user_mfa_recovery_codes
		set used_at = $3
		where id = $1 and user_id = $2 and used_at is null
	`, id, userID, now)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

func (r *MFARepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		delete from user_mfa_recovery_codes
		where used_at is not null and used_at < $1 - interval '30 days'
	`, now)
	return err
}

