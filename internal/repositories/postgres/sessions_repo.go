package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionsRepo struct {
	db *pgxpool.Pool
}

func NewSessionsRepo(db *pgxpool.Pool) *SessionsRepo {
	return &SessionsRepo{db: db}
}

func (r *SessionsRepo) Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO sessions (user_id, device_name, ip_address, user_agent, created_at, last_seen_at)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NOW(), NOW())
		RETURNING id
	`, userID, deviceName, ip, ua).Scan(&id)
	return id, err
}

func (r *SessionsRepo) CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, device_name, ip_address, user_agent, created_at, last_seen_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6, $6)
		ON CONFLICT (id) DO NOTHING
	`, id, userID, deviceName, ip, ua, createdAt)
	return err
}

func (r *SessionsRepo) ListActive(ctx context.Context, userID uuid.UUID) ([]SessionRow, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, device_name, ip_address, user_agent, created_at, last_seen_at, revoked_at
		FROM sessions
		WHERE user_id = $1
		  AND revoked_at IS NULL
		  AND last_seen_at > NOW() - INTERVAL '30 days'
		ORDER BY last_seen_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionRow
	for rows.Next() {
		var s SessionRow
		if err := rows.Scan(&s.ID, &s.UserID, &s.DeviceName, &s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.LastSeenAt, &s.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SessionsRepo) Touch(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET last_seen_at = NOW(),
		    ip_address = COALESCE(NULLIF($2, ''), ip_address),
		    user_agent = COALESCE(NULLIF($3, ''), user_agent),
		    device_name = COALESCE(NULLIF($4, ''), device_name)
		WHERE id = $1 AND revoked_at IS NULL
	`, sessionID, ip, ua, deviceName)
	return err
}

func (r *SessionsRepo) Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`, sessionID)
	return tag.RowsAffected(), err
}

func (r *SessionsRepo) RevokeAllExcept(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE user_id = $1
		  AND id != $2
		  AND revoked_at IS NULL
	`, userID, keepSessionID)
	return tag.RowsAffected(), err
}

func (r *SessionsRepo) GetByID(ctx context.Context, sessionID uuid.UUID) (SessionRow, error) {
	var s SessionRow
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, device_name, ip_address, user_agent, created_at, last_seen_at, revoked_at
		FROM sessions
		WHERE id = $1
	`, sessionID).Scan(&s.ID, &s.UserID, &s.DeviceName, &s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.LastSeenAt, &s.RevokedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return SessionRow{}, nil
		}
		return SessionRow{}, err
	}
	return s, nil
}

func (r *SessionsRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

func (r *SessionsRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM sessions
		WHERE revoked_at IS NOT NULL
		  AND revoked_at < $1 - INTERVAL '30 days'
	`, now)
	return err
}
