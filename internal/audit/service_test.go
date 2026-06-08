package audit_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/MiraiMagicLab/go-platform-kit/internal/audit"
	"github.com/MiraiMagicLab/go-platform-kit/internal/mocks"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
)

func TestAuditService_Log(t *testing.T) {
	var capturedEntry domain.AuditEntry
	userID := uuid.New()

	repo := &mocks.AuditRepoMock{
		CreateFunc: func(ctx context.Context, entry domain.AuditEntry) error {
			capturedEntry = entry
			return nil
		},
	}

	svc := audit.NewAuditService(repo)
	svc.Log(context.Background(), &userID, "auth.login", "success", "127.0.0.1", "test-agent", map[string]interface{}{"key": "value"})

	assert.Equal(t, userID, *capturedEntry.UserID)
	assert.Equal(t, "auth.login", capturedEntry.Action)
	assert.Equal(t, "success", capturedEntry.Status)
	assert.Equal(t, "127.0.0.1", capturedEntry.IP)
	assert.Equal(t, "test-agent", capturedEntry.UserAgent)
}

func TestAuditService_Log_NilRepo(t *testing.T) {
	svc := audit.NewAuditService(nil)
	svc.Log(context.Background(), nil, "test", "success", "", "", nil) // should not panic
}

func TestAuditService_Log_NilMetadata(t *testing.T) {
	var capturedEntry domain.AuditEntry

	repo := &mocks.AuditRepoMock{
		CreateFunc: func(ctx context.Context, entry domain.AuditEntry) error {
			capturedEntry = entry
			return nil
		},
	}

	svc := audit.NewAuditService(repo)
	svc.Log(context.Background(), nil, "test", "success", "", "", nil)

	assert.Nil(t, capturedEntry.Metadata)
}
