package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshTokenRepo provides PostgreSQL-backed persistence for refresh tokens.
type RefreshTokenRepo struct {
	db *pgxpool.Pool
}

// NewRefreshTokenRepo returns a RefreshTokenRepo backed by the given connection pool.
func NewRefreshTokenRepo(db *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

// Create inserts a new refresh token and returns its ID.
func (r *RefreshTokenRepo) Create(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, session_id, token_hash, expires_at, ip_address, user_agent, device_name, last_used_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NOW())
		RETURNING id
	`, userID, sessionID, tokenHash, expiresAt, ip, ua, deviceName).Scan(&id)
	return id, err
}

// GetByHash returns the refresh token matching the given hash.
func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (RefreshTokenDTO, error) {
	var t RefreshTokenDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, session_id, token_hash, expires_at, revoked_at, revoked_reason, created_at, ip_address, user_agent, device_name, last_used_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.SessionID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.RevokedReason, &t.CreatedAt, &t.IPAddress, &t.UserAgent, &t.DeviceName, &t.LastUsedAt)
	return t, err
}

// Revoke marks a single refresh token as revoked with reason "rotated".
// It is a no-op if the token is already revoked.
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

// RevokeAllForUser revokes all active refresh tokens for the given user.
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'logout_all'
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

// RevokeAllForSession ends one login session (all refresh rows with this session_id).
func (r *RefreshTokenRepo) RevokeAllForSession(ctx context.Context, userID, sessionID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'session_revoked'
		WHERE user_id = $1 AND session_id = $2 AND revoked_at IS NULL
	`, userID, sessionID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeAllExceptSession revokes every active refresh token except those belonging to keepSessionID.
func (r *RefreshTokenRepo) RevokeAllExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = 'revoke_other_sessions'
		WHERE user_id = $1 AND session_id <> $2 AND revoked_at IS NULL
	`, userID, keepSessionID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Rotate atomically replaces an old refresh token with a new one inside a transaction.
// If the old token is already revoked or expired, it revokes all tokens for the user (replay detection)
// and returns ReplayDetected=true.
func (r *RefreshTokenRepo) Rotate(ctx context.Context, oldTokenHash, newTokenHash string, newExpiresAt time.Time, clientIP, userAgent, deviceName string) (RotateResult, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RotateResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldID, userID, sessionID uuid.UUID
	var expiresAt time.Time
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, session_id, expires_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, oldTokenHash).Scan(&oldID, &userID, &sessionID, &expiresAt, &revokedAt)
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
			SessionID:      sessionID,
			Invalid:        true,
			ReplayDetected: true,
		}, nil
	}

	var newID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, session_id, token_hash, expires_at, ip_address, user_agent, device_name, last_used_at)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NOW())
		RETURNING id
	`, userID, sessionID, newTokenHash, newExpiresAt, clientIP, userAgent, deviceName).Scan(&newID)
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
		SessionID:         sessionID,
		NewRefreshTokenID: &newID,
	}, nil
}

// Cleanup deletes expired refresh tokens and tokens revoked more than 30 days ago.
func (r *RefreshTokenRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM refresh_tokens
		WHERE expires_at < $1
		   OR (revoked_at IS NOT NULL AND revoked_at < $1 - INTERVAL '30 days')
	`, now)
	return err
}

// ListActiveSessions returns one row per active session (logical device), with metadata from the current refresh token head.
func (r *RefreshTokenRepo) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]SessionListRow, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (rt.session_id)
			rt.session_id,
			rt.id,
			(SELECT MIN(r2.created_at) FROM refresh_tokens r2
			 WHERE r2.user_id = rt.user_id AND r2.session_id = rt.session_id) AS session_started_at,
			rt.last_used_at,
			COALESCE(rt.ip_address, ''),
			COALESCE(rt.user_agent, ''),
			rt.expires_at,
			COALESCE(rt.device_name, '')
		FROM refresh_tokens rt
		WHERE rt.user_id = $1
		  AND rt.revoked_at IS NULL
		  AND rt.expires_at > NOW()
		ORDER BY rt.session_id, rt.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionListRow
	for rows.Next() {
		var s SessionListRow
		if err := rows.Scan(&s.SessionID, &s.RefreshID, &s.CreatedAt, &s.LastUsedAt, &s.IPAddress, &s.UserAgent, &s.ExpiresAt, &s.DeviceName); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
