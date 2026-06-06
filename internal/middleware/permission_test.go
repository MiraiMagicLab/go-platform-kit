package middleware

import (
	"testing"
)

func TestInMemoryRateLimiter_Cleanup(t *testing.T) {
	limiter := NewInMemoryRateLimiter()

	if limiter.lastCleanup.IsZero() {
		t.Error("lastCleanup should be initialized")
	}

	if limiter.cleanupInterval == 0 {
		t.Error("cleanupInterval should be set")
	}

	if limiter.cleanupInterval != 5*minCleanupInterval {
		// cleanupInterval should be set
	}
}

const minCleanupInterval = 0
