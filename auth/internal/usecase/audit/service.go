package audit

import (
	"context"
	"encoding/json"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"

	"github.com/google/uuid"
)

// AuditService writes structured audit events.
type AuditService struct {
	repo ports.AuditRepository
}

func NewAuditService(repo ports.AuditRepository) *AuditService {
	return &AuditService{repo: repo}
}

// Log writes an audit entry. Silently no-ops if repo is nil.
func (s *AuditService) Log(ctx context.Context, userID *uuid.UUID, action, status, ip, userAgent string, metadata map[string]interface{}) {
	if s == nil || s.repo == nil {
		return
	}
	var b json.RawMessage
	if metadata != nil {
		raw, _ := json.Marshal(metadata)
		b = raw
	}
	_ = s.repo.Create(ctx, domain.AuditEntry{
		UserID:    userID,
		Action:    action,
		Status:    status,
		IP:        ip,
		UserAgent: userAgent,
		Metadata:  b,
	})
}
