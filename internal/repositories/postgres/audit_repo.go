package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditRepo provides PostgreSQL-backed persistence for audit log entries.
type AuditRepo struct {
	db *pgxpool.Pool
}

// NewAuditRepo returns an AuditRepo backed by the given connection pool.
func NewAuditRepo(db *pgxpool.Pool) *AuditRepo { return &AuditRepo{db: db} }

// Create inserts a new audit log entry.
func (r *AuditRepo) Create(ctx context.Context, in AuditLogCreate) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO audit_logs (user_id, action, status, ip, user_agent, metadata)
		VALUES ($1, $2, $3, NULLIF($4,''), NULLIF($5,''), $6)
	`, in.UserID, in.Action, in.Status, in.IP, in.UserAgent, in.Metadata)
	return err
}
