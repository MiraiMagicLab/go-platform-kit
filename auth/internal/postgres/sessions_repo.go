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

var _ ports.SessionRepository = (*SessionsRepo)(nil)

// SessionsRepo provides PostgreSQL-backed persistence for user login sessions.
type SessionsRepo struct {
	db *pgxpool.Pool
}

// NewSessionsRepo returns a SessionsRepo backed by the given connection pool.
func NewSessionsRepo(db *pgxpool.Pool) *SessionsRepo {
	return &SessionsRepo{db: db}
}

// Create inserts a new login session and returns its generated ID.
func (r *SessionsRepo) Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO sessions (user_id, device_name, ip_address, user_agent, created_at, last_seen_at)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NOW(), NOW())
		RETURNING id
	`, userID, deviceName, ip, ua).Scan(&id)
	return id, err
}

// CreateWithID inserts a session with an explicit ID. It is a no-op if the ID already exists.
func (r *SessionsRepo) CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, device_name, ip_address, user_agent, created_at, last_seen_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6, $6)
		ON CONFLICT (id) DO NOTHING
	`, id, userID, deviceName, ip, ua, createdAt)
	return err
}

// ListActive returns all non-revoked sessions for the given user that were active within the last 30 days.
func (r *SessionsRepo) ListActive(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	rows, err := r.listActive(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, len(rows))
	for i, row := range rows {
		out[i] = dtoToSession(row)
	}
	return out, nil
}

func (r *SessionsRepo) listActive(ctx context.Context, userID uuid.UUID) ([]SessionRow, error) {
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

// Touch updates the session's last seen time and optionally its IP, user agent, and device name.
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

// Revoke marks the given session as revoked. It returns the number of rows affected.
func (r *SessionsRepo) Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`, sessionID)
	return tag.RowsAffected(), err
}

// RevokeAllExcept revokes all active sessions for the user except the one identified by keepSessionID.
// It returns the number of rows affected.
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

// GetByID returns the session with the given ID. If no session exists, it returns a zero-value Session and nil error.
func (r *SessionsRepo) GetByID(ctx context.Context, sessionID uuid.UUID) (domain.Session, error) {
	row, err := r.getByID(ctx, sessionID)
	if err != nil {
		return domain.Session{}, err
	}
	return dtoToSession(row), nil
}

func (r *SessionsRepo) getByID(ctx context.Context, sessionID uuid.UUID) (SessionRow, error) {
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

// RevokeAllForUser revokes all active sessions for the given user.
func (r *SessionsRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

// Cleanup deletes sessions that were revoked more than 30 days ago.
func (r *SessionsRepo) Cleanup(ctx context.Context, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM sessions
		WHERE revoked_at IS NOT NULL
		  AND revoked_at < $1 - INTERVAL '30 days'
	`, now)
	return err
}

func dtoToSession(row SessionRow) domain.Session {
	return domain.Session{
		ID:         row.ID,
		UserID:     row.UserID,
		DeviceName: row.DeviceName,
		IPAddress:  row.IPAddress,
		UserAgent:  row.UserAgent,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
		RevokedAt:  row.RevokedAt,
	}
}
