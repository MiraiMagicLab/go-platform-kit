package ports

import (
	"context"
	"time"
)

// AccessTokenDenylist defines operations for denying access tokens by JTI.
type AccessTokenDenylist interface {
	IsDenied(ctx context.Context, jti string) (bool, error)
	Deny(ctx context.Context, jti string, ttl time.Duration) error
}

// NoopAccessTokenDenylist is a no-op implementation of AccessTokenDenylist.
type NoopAccessTokenDenylist struct{}

func (NoopAccessTokenDenylist) IsDenied(context.Context, string) (bool, error) {
	return false, nil
}
func (NoopAccessTokenDenylist) Deny(context.Context, string, time.Duration) error { return nil }
