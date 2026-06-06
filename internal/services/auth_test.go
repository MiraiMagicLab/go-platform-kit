package services

import (
	"testing"
	"time"
)

func TestIsAccountLocked(t *testing.T) {
	future := time.Now().Add(1 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	if !isAccountLocked(&future) {
		t.Error("expected true for future lock")
	}
	if isAccountLocked(&past) {
		t.Error("expected false for past lock")
	}
	if isAccountLocked(nil) {
		t.Error("expected false for nil")
	}
}

func TestIsUserDeleted(t *testing.T) {
	now := time.Now()
	if !isUserDeleted(&now) {
		t.Error("expected true for set deletedAt")
	}
	if isUserDeleted(nil) {
		t.Error("expected false for nil deletedAt")
	}
}

func TestAuthServiceConfigDefaults(t *testing.T) {
	svc := NewAuthService(nil, nil, nil, nil, nil, nil, 0, 0, "", false, 0, 0)
	if svc.maxFailedAttempts != 5 {
		t.Errorf("expected default maxFailedAttempts=5, got %d", svc.maxFailedAttempts)
	}
	if svc.lockDuration != 15*time.Minute {
		t.Errorf("expected default lockDuration=15m, got %v", svc.lockDuration)
	}
}
