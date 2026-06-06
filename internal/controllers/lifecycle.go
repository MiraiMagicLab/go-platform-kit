package controllers

import (
	"context"

	"github.com/google/uuid"
)

// AuthLifecycle carries optional callbacks wired from authkit.Config.Hooks (same package boundary as handlers).
type AuthLifecycle struct {
	// AfterSessionIssued is called after tokens are successfully issued for register, login,
	// OAuth callback, or MFA completion. It runs in a new goroutine with context.Background()
	// (request context is not used to avoid cancellation when the HTTP handler returns).
	// Implementations must return quickly: enqueue to your own outbox/queue and process async.
	// Email is set when known (e.g. password register/login); nil for OAuth/MFA-only flows.
	AfterSessionIssued func(ctx context.Context, reason string, userID uuid.UUID, email *string, clientIP, userAgent string)
}

// fireAfterSessionIssued fires AfterSessionIssued asynchronously in a goroutine.
// Nil checks are the caller's responsibility.
func fireAfterSessionIssued(lc *AuthLifecycle, reason string, userID uuid.UUID, email *string, clientIP, userAgent string) {
	if lc == nil || lc.AfterSessionIssued == nil {
		return
	}
	fn := lc.AfterSessionIssued
	go func() {
		defer func() { recover() }()
		fn(context.Background(), reason, userID, email, clientIP, userAgent)
	}()
}
