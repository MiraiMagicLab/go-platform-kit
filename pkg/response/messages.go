package response

var commonMessages = map[string]string{
	// System — M0000xxx
	CodeUnknownError: "An unexpected error occurred",
	CodeBadRequest:   "Invalid request",
	CodeUnauthorized: "Authentication required",
	CodeForbidden:    "Access denied",
	CodeNotFound:     "Resource not found",
	CodeConflict:     "Resource conflict",
	CodeRateLimited:  "Too many requests, please try again later",
	CodeInternal:     "Internal server error",

	// Auth — M0001xxx
	CodeAuthInvalidCredentials:  "Invalid credentials",
	CodeAuthInvalidEmail:        "Invalid email format",
	CodeAuthInvalidPassword:     "Password must be at least 8 characters",
	CodeAuthTokenInvalid:        "Invalid token",
	CodeAuthTokenExpired:        "Token expired",
	CodeAuthTokenRevoked:        "Token revoked",
	CodeAuthInvalidRefresh:      "Invalid refresh token",
	CodeAuthEmailNotVerified:    "Email address is not verified",
	CodeAuthUserBanned:          "User is temporarily banned",
	CodeAuthAccountLocked:       "Account is temporarily locked due to too many failed login attempts",
	CodeAuthRegisterFailed:      "Could not register user",
	CodeAuthLogoutFailed:        "Could not logout",
	CodeAuthPasswordResetFailed: "Could not reset password",
	CodeAuthEmailSendFailed:     "Could not send email",
	CodeAuthInvalidActionToken:  "Invalid or expired token",
	CodeAuthInvalidMFA:          "Invalid MFA code",

	// Session — M0002xxx
	CodeSessionNotFound:     "Session not found or already revoked",
	CodeSessionNoSIDInToken: "Operation requires a session-scoped access token",

	// RBAC — M0003xxx
	CodeRBACCreateRoleFailed:       "Could not create role",
	CodeRBACCreatePermissionFailed: "Could not create permission",
	CodeRBACAssignFailed:           "Could not assign",

	// MFA — M0004xxx
	CodeMFASetupFailed:   "Could not setup MFA",
	CodeMFAEnableFailed:  "Could not enable MFA",
	CodeMFADisableFailed: "Could not disable MFA",

	// OAuth — M0005xxx
	CodeOAuthStateInvalid:  "Invalid OAuth state",
	CodeOAuthExchangeFail:  "OAuth exchange failed",
	CodeOAuthUserFail:      "OAuth user processing failed",
	CodeOAuthNotConfigured: "OAuth provider is not configured",
}
