package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

var _ ports.MFARepository = (*MFARepo)(nil)

// MFARepo provides PostgreSQL-backed persistence for multi-factor authentication state.
type MFARepo struct {
	db *pgxpool.Pool
}

// NewMFARepo returns an MFARepo backed by the given connection pool.
func NewMFARepo(db *pgxpool.Pool) *MFARepo { return &MFARepo{db: db} }

// UpsertTOTPSecret inserts or updates the TOTP secret for the given user.
// It sets the MFA state to disabled, requiring a separate EnableMFA call to activate.
func (r *MFARepo) UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_mfa (user_id, totp_secret, enabled)
		VALUES ($1, $2, false)
		ON CONFLICT (user_id)
		DO UPDATE SET totp_secret = EXCLUDED.totp_secret, enabled = false, enabled_at = NULL
	`, userID, secret)
	return err
}

// GetMFA returns the MFA record for the given user.
// If no record exists, it returns false with a nil error.
func (r *MFARepo) GetMFA(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error) {
	dto, ok, err := r.getMFA(ctx, userID)
	if err != nil {
		return domain.MFAConfig{}, false, err
	}
	if !ok {
		return domain.MFAConfig{}, false, nil
	}
	return dtoToMFAConfig(dto), true, nil
}

func (r *MFARepo) getMFA(ctx context.Context, userID uuid.UUID) (MFADTO, bool, error) {
	var m MFADTO
	err := r.db.QueryRow(ctx, `
		SELECT user_id, totp_secret, enabled, enabled_at, created_at
		FROM user_mfa
		WHERE user_id = $1
	`, userID).Scan(&m.UserID, &m.TOTPSecret, &m.Enabled, &m.EnabledAt, &m.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return MFADTO{}, false, nil
		}
		return MFADTO{}, false, err
	}
	return m, true, nil
}

// EnableMFA activates MFA for the given user and records the activation time.
func (r *MFARepo) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE user_mfa
		SET enabled = true, enabled_at = NOW()
		WHERE user_id = $1
	`, userID)
	return err
}

// DisableMFA removes the MFA record and all associated recovery codes for the given user.
func (r *MFARepo) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM user_mfa WHERE user_id = $1
	`, userID)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`, userID)
	return err
}

// ReplaceRecoveryCodes atomically replaces all recovery codes for the given user within a transaction.
// Existing codes are deleted before the new set is inserted.
func (r *MFARepo) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}

	batch := &pgx.Batch{}
	for _, h := range codeHashes {
		batch.Queue(`
			INSERT INTO user_mfa_recovery_codes (user_id, code_hash)
			VALUES ($1, $2)
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

// UseRecoveryCode marks a matching unused recovery code as used.
// It returns true if the code was valid and consumed, false if no matching unused code was found.
func (r *MFARepo) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		SELECT id
		FROM user_mfa_recovery_codes
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		LIMIT 1
	`, userID, codeHash).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	now := time.Now()
	ct, err := r.db.Exec(ctx, `
		UPDATE user_mfa_recovery_codes
		SET used_at = $3
		WHERE id = $1 AND user_id = $2 AND used_at IS NULL
	`, id, userID, now)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

// Cleanup deletes recovery codes that were used more than 30 days ago.
func (r *MFARepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM user_mfa_recovery_codes
		WHERE used_at IS NOT NULL AND used_at < $1 - INTERVAL '30 days'
	`, now)
	return err
}

func dtoToMFAConfig(dto MFADTO) domain.MFAConfig {
	return domain.MFAConfig{
		UserID:     dto.UserID,
		TOTPSecret: dto.TOTPSecret,
		Enabled:    dto.Enabled,
		EnabledAt:  dto.EnabledAt,
		CreatedAt:  dto.CreatedAt,
	}
}
