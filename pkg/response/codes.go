package response

const (
	CodeAuthInvalidCredentials  = "auth.invalid.credentials"
	CodeAuthInvalidEmail        = "auth.invalid.email"
	CodeAuthInvalidPassword     = "auth.invalid.password"
	CodeAuthInvalidToken        = "auth.token.invalid"
	CodeAuthTokenExpired        = "auth.token.expired"
	CodeAuthTokenRevoked        = "auth.token.revoked"
	CodeAuthUnauthorized        = "auth.unauthorized"
	CodeAuthForbidden           = "auth.forbidden"
	CodeAuthInvalidRefresh      = "auth.token.invalid_refresh"
	CodeAuthInvalidMFA          = "auth.invalid.mfa"
	CodeAuthRegisterFailed      = "auth.action.register_fail"
	CodeAuthLogoutFailed        = "auth.action.logout_fail"
	CodeAuthEmailSendFailed     = "auth.email.send_fail"
	CodeAuthInvalidActionToken  = "auth.token.invalid_action"
	CodeAuthPasswordResetFailed = "auth.action.password_reset_fail"
	CodeAuthEmailNotVerified    = "auth.email.not_verified"
	CodeAuthUserBanned          = "auth.user.banned"

	CodeRBACCreateRoleFailed       = "rbac.action.create_role_fail"
	CodeRBACCreatePermissionFailed = "rbac.action.create_permission_fail"
	CodeRBACAssignFailed           = "rbac.action.assign_fail"

	CodeMFASetupFailed   = "mfa.action.setup_fail"
	CodeMFAEnableFailed  = "mfa.action.enable_fail"
	CodeMFADisableFailed = "mfa.action.disable_fail"

	CodeOAuthStateInvalid  = "oauth.invalid.state"
	CodeOAuthExchangeFail  = "oauth.action.exchange_fail"
	CodeOAuthUserFail      = "oauth.action.user_fail"
	CodeOAuthNotConfigured = "oauth.config.not_found"

	CodeCommonBadRequest      = "common.invalid.request"
	CodeCommonInternal        = "common.system.error"
	CodeCommonTooManyRequests = "common.rate_limit.error"
	CodeCommonNotFound        = "common.resource.not_found"
)

var defaultMessages = map[string]string{
	CodeAuthInvalidCredentials:  "Invalid credentials",
	CodeAuthInvalidEmail:        "Invalid email format",
	CodeAuthInvalidPassword:     "Password must be at least 8 characters",
	CodeAuthInvalidToken:        "Invalid token",
	CodeAuthTokenExpired:        "Token expired",
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

// MergeDefaultMessages registers additional code -> defaultMessage entries
// for host applications (e.g. lingo-engine) so FailCode can resolve user-facing text.
func MergeDefaultMessages(extra map[string]string) {
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		defaultMessages[k] = v
	}
}
