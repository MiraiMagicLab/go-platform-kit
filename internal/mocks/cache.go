package mocks

import (
	"context"
	"time"

	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

var _ ports.StringSliceCache = (*StringSliceCacheMock)(nil)

// StringSliceCacheMock is a mock implementation of ports.StringSliceCache for testing.
type StringSliceCacheMock struct {
	GetFunc func(ctx context.Context, key string) ([]string, bool, error)
	SetFunc func(ctx context.Context, key string, value []string, ttl time.Duration) error
	DelFunc func(ctx context.Context, key string) error
}

func (m *StringSliceCacheMock) Get(ctx context.Context, key string) ([]string, bool, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, key)
	}
	return nil, false, nil
}

func (m *StringSliceCacheMock) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	if m.SetFunc != nil {
		return m.SetFunc(ctx, key, value, ttl)
	}
	return nil
}

func (m *StringSliceCacheMock) Del(ctx context.Context, key string) error {
	if m.DelFunc != nil {
		return m.DelFunc(ctx, key)
	}
	return nil
}
