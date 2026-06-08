package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.AccessTokenDenylist = (*DenylistMock)(nil)

// DenylistMock is a mock implementation of ports.AccessTokenDenylist for testing.
type DenylistMock struct {
	mu sync.RWMutex

	IsDeniedFunc func(ctx context.Context, jti string) (bool, error)
	DenyFunc     func(ctx context.Context, jti string, ttl time.Duration) error

	// State tracking
	denied map[string]struct{}
}

func NewDenylistMock() *DenylistMock {
	return &DenylistMock{denied: make(map[string]struct{})}
}

func (m *DenylistMock) IsDenied(ctx context.Context, jti string) (bool, error) {
	if m.IsDeniedFunc != nil {
		return m.IsDeniedFunc(ctx, jti)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.denied[jti]
	return ok, nil
}

func (m *DenylistMock) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if m.DenyFunc != nil {
		return m.DenyFunc(ctx, jti, ttl)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.denied[jti] = struct{}{}
	return nil
}

// IsDeniedJTI checks if a JTI was denied (for test assertions).
func (m *DenylistMock) IsDeniedJTI(jti string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.denied[jti]
	return ok
}
