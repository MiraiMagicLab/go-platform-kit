package auth

import (
	"context"

	"github.com/google/uuid"
)

// SessionIssuedReason describes why a new access/refresh session was issued to the user.
type SessionIssuedReason string

const (
	SessionIssuedRegister    SessionIssuedReason = "register"
	SessionIssuedLogin       SessionIssuedReason = "login"
	SessionIssuedOAuth       SessionIssuedReason = "oauth"
	SessionIssuedMFAComplete SessionIssuedReason = "mfa_complete"
)

// Hooks allows host projects to customize non-security-critical integration points.
type Hooks struct {
	BuildVerifyEmailLink   func(publicBaseURL, rawToken string) string
	BuildResetPasswordLink func(publicBaseURL, rawToken string) string
	RenderVerifyEmail      func(link string) (subject string, body string)
	RenderResetPassword    func(link string) (subject string, body string)
	AfterSessionIssued     func(ctx context.Context, reason SessionIssuedReason, userID uuid.UUID, email *string, clientIP, userAgent string)
}
