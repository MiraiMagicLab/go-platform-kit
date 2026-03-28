package response

const (
	CodeAuthInvalidCredentials  = "auth.invalid_credentials"
	CodeAuthInvalidEmail        = "auth.invalid_email"
	CodeAuthInvalidPassword     = "auth.invalid_password"
	CodeAuthInvalidToken        = "auth.invalid_token"
	CodeAuthTokenRevoked        = "auth.token_revoked"
	CodeAuthUnauthorized        = "auth.unauthorized"
	CodeAuthForbidden           = "auth.forbidden"
	CodeAuthInvalidRefresh      = "auth.invalid_refresh_token"
	CodeAuthInvalidMFA          = "auth.invalid_mfa"
	CodeAuthRegisterFailed      = "auth.register_failed"
	CodeAuthLogoutFailed        = "auth.logout_failed"
	CodeAuthEmailSendFailed     = "auth.email_send_failed"
	CodeAuthInvalidActionToken  = "auth.invalid_action_token"
	CodeAuthPasswordResetFailed = "auth.password_reset_failed"
	CodeAuthEmailNotVerified    = "auth.email_not_verified"
	CodeAuthUserBanned          = "auth.user_banned"

	CodeRBACCreateRoleFailed       = "rbac.create_role_failed"
	CodeRBACCreatePermissionFailed = "rbac.create_permission_failed"
	CodeRBACAssignFailed           = "rbac.assign_failed"

	CodeMFASetupFailed   = "mfa.setup_failed"
	CodeMFAEnableFailed  = "mfa.enable_failed"
	CodeMFADisableFailed = "mfa.disable_failed"

	CodeOAuthStateInvalid  = "oauth.invalid_state"
	CodeOAuthExchangeFail  = "oauth.exchange_failed"
	CodeOAuthUserFail      = "oauth.user_failed"
	CodeOAuthNotConfigured = "oauth.not_configured"

	CodeCommonBadRequest      = "common.bad_request"
	CodeCommonInternal        = "common.internal_error"
	CodeCommonTooManyRequests = "common.too_many_requests"
	CodeCommonNotFound        = "common.not_found"
)

var defaultMessages = map[string]string{
	CodeAuthInvalidCredentials:  "Invalid credentials",
	CodeAuthInvalidEmail:        "Invalid email format",
	CodeAuthInvalidPassword:     "Password must be at least 8 characters",
	CodeAuthInvalidToken:        "Invalid token",
	CodeAuthTokenRevoked:        "Token revoked",
	CodeAuthUnauthorized:        "Unauthorized",
	CodeAuthForbidden:           "Forbidden",
	CodeAuthInvalidRefresh:      "Invalid refresh token",
	CodeAuthInvalidMFA:          "Invalid MFA code",
	CodeAuthRegisterFailed:      "Could not register user",
	CodeAuthLogoutFailed:        "Could not logout",
	CodeAuthEmailSendFailed:     "Could not send email",
	CodeAuthInvalidActionToken:  "Invalid or expired token",
	CodeAuthPasswordResetFailed: "Could not reset password",
	CodeAuthEmailNotVerified:    "Email address is not verified",
	CodeAuthUserBanned:          "User is temporarily banned",

	CodeRBACCreateRoleFailed:       "Could not create role",
	CodeRBACCreatePermissionFailed: "Could not create permission",
	CodeRBACAssignFailed:           "Could not assign",

	CodeMFASetupFailed:   "Could not setup MFA",
	CodeMFAEnableFailed:  "Could not enable MFA",
	CodeMFADisableFailed: "Could not disable MFA",

	CodeOAuthStateInvalid:  "Invalid OAuth state",
	CodeOAuthExchangeFail:  "OAuth exchange failed",
	CodeOAuthUserFail:      "OAuth user processing failed",
	CodeOAuthNotConfigured: "OAuth provider is not configured",

	CodeCommonBadRequest:      "Invalid request body",
	CodeCommonInternal:        "Internal server error",
	CodeCommonTooManyRequests: "Too many requests, please try again later",
	CodeCommonNotFound:        "Not found",

	// Example for positional placeholder support.
	"test.multi_param": "Hello {0}, you have {1} new messages in your {2} bucket.",
}

func DefaultMessage(code string) string {
	if msg, ok := defaultMessages[code]; ok {
		return msg
	}
	// Fallback requested by user: use code itself as message.
	return code
}

// MergeDefaultMessages registers additional errorCode -> defaultMessage entries
// for host applications (e.g. lingo-engine) so FailCode can resolve user-facing text.
func MergeDefaultMessages(extra map[string]string) {
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		defaultMessages[k] = v
	}
}
