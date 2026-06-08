package postgres

import (
	"context"

	"github.com/MiraiMagicLab/go-platform-kit/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.AuditRepository = (*AuditAdapter)(nil)

// AuditAdapter wraps *postgres.AuditRepo to implement ports.AuditRepository.
type AuditAdapter struct {
	repo *postgres.AuditRepo
}

func NewAuditAdapter(repo *postgres.AuditRepo) *AuditAdapter {
	return &AuditAdapter{repo: repo}
}

func (a *AuditAdapter) Create(ctx context.Context, entry domain.AuditEntry) error {
	return a.repo.Create(ctx, postgres.AuditLogCreate{
		UserID:    entry.UserID,
		Action:    entry.Action,
		Status:    entry.Status,
		IP:        entry.IP,
		UserAgent: entry.UserAgent,
		Metadata:  entry.Metadata,
	})
}
