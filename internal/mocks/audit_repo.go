package mocks

import (
	"context"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.AuditRepository = (*AuditRepoMock)(nil)

// AuditRepoMock is a mock implementation of ports.AuditRepository for testing.
type AuditRepoMock struct {
	CreateFunc func(ctx context.Context, entry domain.AuditEntry) error
}

func (m *AuditRepoMock) Create(ctx context.Context, entry domain.AuditEntry) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, entry)
	}
	return nil
}
