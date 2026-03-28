package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditRepo struct {
	db *pgxpool.Pool
}

func NewAuditRepo(db *pgxpool.Pool) *AuditRepo { return &AuditRepo{db: db} }

func (r *AuditRepo) Create(ctx context.Context, in AuditLogCreate) error {
	_, err := r.db.Exec(ctx, `
		insert into audit_logs (user_id, action, status, ip, user_agent, metadata)
		values ($1, $2, $3, nullif($4,''), nullif($5,''), $6)
	`, in.UserID, in.Action, in.Status, in.IP, in.UserAgent, in.Metadata)
	return err
}

