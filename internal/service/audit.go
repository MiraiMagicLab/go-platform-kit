package service

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/repository"
)

type AuditService struct {
	repo repository.AuditRepository
}

func NewAuditService(repo repository.AuditRepository) *AuditService { return &AuditService{repo: repo} }

func (s *AuditService) Log(ctx context.Context, userID *uuid.UUID, action, status, ip, userAgent string, metadata map[string]interface{}) {
	if s == nil || s.repo == nil {
		return
	}
	var b json.RawMessage
	if metadata != nil {
		raw, _ := json.Marshal(metadata)
		b = raw
	}
	_ = s.repo.Create(ctx, repository.AuditLogCreate{
		UserID:    userID,
		Action:    action,
		Status:    status,
		IP:        ip,
		UserAgent: userAgent,
		Metadata:  b,
	})
}
