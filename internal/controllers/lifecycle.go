package controllers

import (
	"context"

	"github.com/google/uuid"
)

// AuthLifecycle carries optional callbacks wired from authkit.Config.Hooks (same package boundary as handlers).
type AuthLifecycle struct {
	AfterSessionIssued func(ctx context.Context, reason string, userID uuid.UUID, email *string, clientIP, userAgent string)
}

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
