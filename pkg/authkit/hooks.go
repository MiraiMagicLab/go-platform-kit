package authkit

import (
	"context"

	"github.com/google/uuid"
)

// SessionIssuedReason describes why a new access/refresh session was issued to the user.
// Use these values with AfterSessionIssued.
type SessionIssuedReason string

const (
	SessionIssuedRegister    SessionIssuedReason = "register"
	SessionIssuedLogin       SessionIssuedReason = "login"
	SessionIssuedOAuth       SessionIssuedReason = "oauth"
	SessionIssuedMFAComplete SessionIssuedReason = "mfa_complete"
)

// Hooks allows host projects to customize non-security-critical integration points
// (e.g. email links/templates) while keeping core auth logic consistent.
type Hooks struct {
	// BuildVerifyEmailLink returns a link sent to the user for email verification.
	// If nil, a default link under {PublicBaseURL}/auth is used.
	BuildVerifyEmailLink func(publicBaseURL, rawToken string) string

	// BuildResetPasswordLink returns a link sent to the user to reset password.
	// If nil, a default link under {PublicBaseURL}/auth is used.
	BuildResetPasswordLink func(publicBaseURL, rawToken string) string

	// RenderVerifyEmail returns subject/body for verify email email.
	// If nil, default plaintext is used.
	RenderVerifyEmail func(link string) (subject string, body string)

	// RenderResetPassword returns subject/body for reset password email.
	// If nil, default plaintext is used.
	RenderResetPassword func(link string) (subject string, body string)

	// AfterSessionIssued is called after tokens are successfully issued for register, login,
	// OAuth callback, or MFA completion. It runs in a new goroutine with context.Background()
	// (request context is not used to avoid cancellation when the HTTP handler returns).
	// Implementations must return quickly: enqueue to your own outbox/queue and process async.
	// Email is set when known (e.g. password register/login); nil for OAuth/MFA-only flows.
	AfterSessionIssued func(ctx context.Context, reason SessionIssuedReason, userID uuid.UUID, email *string, clientIP, userAgent string)
}
