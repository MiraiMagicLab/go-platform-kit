package domain

import (
	"errors"
	"time"
)

// Sentinel errors for authentication flows.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
	ErrSessionNotFound    = errors.New("session not found or already revoked")
)

// ErrAccountLocked is returned when the account is temporarily locked due to too many failed attempts.
type ErrAccountLocked struct {
	Until *time.Time
}

func (e ErrAccountLocked) Error() string { return "account is locked" }

// ErrUserBanned is returned when the user is banned.
type ErrUserBanned struct {
	Until  *time.Time
	Reason *string
}

func (e ErrUserBanned) Error() string { return "user is banned" }

// ErrEmailNotVerified is returned when email verification is required but not completed.
type ErrEmailNotVerified struct{}

func (e ErrEmailNotVerified) Error() string { return "email not verified" }

// ErrMFARequired is returned when MFA verification is needed to complete login.
type ErrMFARequired struct {
	MFAToken string
}

func (e ErrMFARequired) Error() string { return "mfa required" }
