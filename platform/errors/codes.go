package errors

// Success codes (optional client i18n for non-error outcomes).
const (
	CodeSuccess   = "S0000000"
	CodeCreated   = "S0000001"
	CodeUpdated   = "S0000002"
	CodeDeleted   = "S0000003"
	CodeNoContent = "S0000004"
)

// Platform wire codes aligned with Mirai Java MessageCodes (Mxxxx).
// Auth client buckets (Soybean-admin pattern):
//
//	M0200 → silent logout
//	M0201 → refresh access token then retry (never return from /auth/refresh)
//	M0202 → modal logout (invalid / revoked / bad refresh)
//	M0203 → credentials error (login form; do not logout)
//
// See ERROR_CODE_REFERENCE.md.
const (
	CodeUnknownError = "M0900"
	CodeBadRequest   = "M0100"
	CodeUnauthorized = "M0200"
	CodeForbidden    = "M0250"
	CodeNotFound     = "M0300"
	CodeConflict     = "M0301"
	CodeRateLimited  = "M0105"
	CodeInternal     = "M0900"
)

// Auth
const (
	CodeAuthInvalidCredentials  = "M0203"
	CodeAuthInvalidEmail        = "M0100"
	CodeAuthInvalidPassword     = "M0100"
	CodeAuthTokenInvalid        = "M0202"
	CodeAuthTokenExpired        = "M0201"
	CodeAuthTokenRevoked        = "M0202"
	CodeAuthInvalidRefresh      = "M0202"
	CodeAuthEmailNotVerified    = "M0252"
	CodeAuthUserBanned          = "M0252"
	CodeAuthAccountLocked       = "M0251"
	CodeAuthRegisterFailed      = "M0400"
	CodeAuthLogoutFailed        = "M0900"
	CodeAuthPasswordResetFailed = "M0400"
	CodeAuthEmailSendFailed     = "M0800"
	CodeAuthInvalidActionToken  = "M0202"
	CodeAuthInvalidMFA          = "M0203"
)

// Session
const (
	CodeSessionNotFound     = "M0300"
	CodeSessionNoSIDInToken = "M0202"
)

// RBAC / MFA / OAuth — share Mirai business/system codes when no dedicated MessageCode exists.
const (
	CodeRBACCreateRoleFailed       = "M0400"
	CodeRBACCreatePermissionFailed = "M0400"
	CodeRBACAssignFailed           = "M0400"

	CodeMFASetupFailed   = "M0400"
	CodeMFAEnableFailed  = "M0400"
	CodeMFADisableFailed = "M0400"

	CodeOAuthStateInvalid  = "M0100"
	CodeOAuthExchangeFail  = "M0800"
	CodeOAuthUserFail      = "M0800"
	CodeOAuthNotConfigured = "M0400"
)
