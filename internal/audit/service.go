package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
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
