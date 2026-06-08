package ports

import (
	"context"
	"time"
)

// StringSliceCache defines a cache for string slices (used for permission caching).
type StringSliceCache interface {
	Get(ctx context.Context, key string) ([]string, bool, error)
	Set(ctx context.Context, key string, value []string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// NoopStringSliceCache is a no-op implementation of StringSliceCache.
type NoopStringSliceCache struct{}

func (NoopStringSliceCache) Get(context.Context, string) ([]string, bool, error) {
	return nil, false, nil
}
func (NoopStringSliceCache) Set(context.Context, string, []string, time.Duration) error {
	return nil
}
func (NoopStringSliceCache) Del(context.Context, string) error { return nil }
