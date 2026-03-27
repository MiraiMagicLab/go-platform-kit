package authkit

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
}
