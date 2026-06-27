package response

// Platform Common error codes (PP=00). These codes are shared across all products
// and correspond to standard HTTP error categories.
//
// Code format: M + 2-digit product (00) + 2-digit category (00) + 3-digit sequence.
// See ERROR_CODE_REFERENCE.md for the complete specification.
const (
	// CodeUnknownError is returned when an unexpected error occurs.
	CodeUnknownError = "M0000000"
	// CodeBadRequest indicates malformed or invalid request input.
	CodeBadRequest = "M0000001"
	// CodeUnauthorized indicates missing or invalid authentication.
	CodeUnauthorized = "M0000002"
	// CodeForbidden indicates the authenticated user lacks required permissions.
	CodeForbidden = "M0000003"
	// CodeNotFound indicates the requested resource does not exist.
	CodeNotFound = "M0000004"
	// CodeConflict indicates a resource state conflict such as a duplicate entry.
	CodeConflict = "M0000005"
	// CodeRateLimited indicates the client exceeded the allowed request rate.
	CodeRateLimited = "M0000006"
	// CodeInternal indicates an unexpected server-side error.
	CodeInternal = "M0000007"
)

// ── Auth (PP=00, CC=01) ─────────────────────────────────────────────────

const (
	// CodeAuthInvalidCredentials indicates the supplied email or password is incorrect.
	CodeAuthInvalidCredentials = "M0001001"
	// CodeAuthInvalidEmail indicates the email address failed format validation.
	CodeAuthInvalidEmail = "M0001002"
	// CodeAuthInvalidPassword indicates the password does not meet minimum requirements.
	CodeAuthInvalidPassword = "M0001003"
	// CodeAuthTokenInvalid indicates the JWT token is malformed or has an invalid signature.
	CodeAuthTokenInvalid = "M0001004"
	// CodeAuthTokenExpired indicates the JWT token has passed its expiration time.
	CodeAuthTokenExpired = "M0001005"
	// CodeAuthTokenRevoked indicates the JWT token has been explicitly revoked.
	CodeAuthTokenRevoked = "M0001006"
	// CodeAuthInvalidRefresh indicates the refresh token is invalid, expired, or already rotated.
	CodeAuthInvalidRefresh = "M0001007"
	// CodeAuthEmailNotVerified indicates the user's email address has not been verified.
	CodeAuthEmailNotVerified = "M0001008"
	// CodeAuthUserBanned indicates the user account is currently banned.
	CodeAuthUserBanned = "M0001009"
	// CodeAuthAccountLocked indicates the user account is temporarily locked due to failed login attempts.
	CodeAuthAccountLocked = "M0001010"
	// CodeAuthRegisterFailed indicates user registration could not be completed.
	CodeAuthRegisterFailed = "M0001011"
	// CodeAuthLogoutFailed indicates the logout operation could not be completed.
	CodeAuthLogoutFailed = "M0001012"
	// CodeAuthPasswordResetFailed indicates the password reset could not be completed.
	CodeAuthPasswordResetFailed = "M0001013"
	// CodeAuthEmailSendFailed indicates the verification or reset email could not be sent.
	CodeAuthEmailSendFailed = "M0001014"
	// CodeAuthInvalidActionToken indicates the email action token is invalid or expired.
	CodeAuthInvalidActionToken = "M0001015"
	// CodeAuthInvalidMFA indicates the MFA verification code is incorrect or the challenge token is invalid.
	CodeAuthInvalidMFA = "M0001016"
)

// ── Session (PP=00, CC=02) ──────────────────────────────────────────────

const (
	// CodeSessionNotFound indicates the requested session does not exist or has been revoked.
	CodeSessionNotFound = "M0002001"
	// CodeSessionNoSIDInToken indicates the access token does not contain a session ID claim.
	CodeSessionNoSIDInToken = "M0002002"
)

// ── RBAC (PP=00, CC=03) ────────────────────────────────────────────────

const (
	// CodeRBACCreateRoleFailed indicates role creation could not be completed.
	CodeRBACCreateRoleFailed = "M0003001"
	// CodeRBACCreatePermissionFailed indicates permission creation could not be completed.
	CodeRBACCreatePermissionFailed = "M0003002"
	// CodeRBACAssignFailed indicates the role or permission assignment could not be completed.
	CodeRBACAssignFailed = "M0003003"
)

// ── MFA (PP=00, CC=04) ─────────────────────────────────────────────────

const (
	// CodeMFASetupFailed indicates TOTP setup could not be completed.
	CodeMFASetupFailed = "M0004001"
	// CodeMFAEnableFailed indicates TOTP enablement could not be completed (e.g. invalid code).
	CodeMFAEnableFailed = "M0004002"
	// CodeMFADisableFailed indicates MFA disable could not be completed.
	CodeMFADisableFailed = "M0004003"
)

// ── OAuth (PP=00, CC=05) ───────────────────────────────────────────────

const (
	// CodeOAuthStateInvalid indicates the OAuth CSRF state cookie does not match the callback parameter.
	CodeOAuthStateInvalid = "M0005001"
	// CodeOAuthExchangeFail indicates the OAuth authorization code exchange failed.
	CodeOAuthExchangeFail = "M0005002"
	// CodeOAuthUserFail indicates user lookup or creation from OAuth identity failed.
	CodeOAuthUserFail = "M0005003"
	// CodeOAuthNotConfigured indicates the requested OAuth provider is not configured.
	CodeOAuthNotConfigured = "M0005004"
)
