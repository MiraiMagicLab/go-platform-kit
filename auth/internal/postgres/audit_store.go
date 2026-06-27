package postgres

import (
	"context"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
)

var _ store.AuditRepository = (*AuditAdapter)(nil)

// AuditAdapter wraps *AuditRepo to implement store.AuditRepository.
type AuditAdapter struct {
	repo *AuditRepo
}

func NewAuditAdapter(repo *AuditRepo) *AuditAdapter {
	return &AuditAdapter{repo: repo}
}

func (a *AuditAdapter) Create(ctx context.Context, entry domain.AuditEntry) error {
	return a.repo.Create(ctx, AuditLogCreate{
		UserID:    entry.UserID,
		Action:    entry.Action,
		Status:    entry.Status,
		IP:        entry.IP,
		UserAgent: entry.UserAgent,
		Metadata:  entry.Metadata,
	})
}
