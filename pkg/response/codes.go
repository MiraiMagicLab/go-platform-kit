package response

// ── Platform Common (PP=00) ──────────────────────────────────────────────

const (
	CodeUnknownError = "M0000000"
	CodeBadRequest   = "M0000001"
	CodeUnauthorized = "M0000002"
	CodeForbidden    = "M0000003"
	CodeNotFound     = "M0000004"
	CodeConflict     = "M0000005"
	CodeRateLimited  = "M0000006"
	CodeInternal     = "M0000007"
)

// ── Auth (PP=00, CC=01) ─────────────────────────────────────────────────

const (
	CodeAuthInvalidCredentials  = "M0001001"
	CodeAuthInvalidEmail        = "M0001002"
	CodeAuthInvalidPassword     = "M0001003"
	CodeAuthTokenInvalid        = "M0001004"
	CodeAuthTokenExpired        = "M0001005"
	CodeAuthTokenRevoked        = "M0001006"
	CodeAuthInvalidRefresh      = "M0001007"
	CodeAuthEmailNotVerified    = "M0001008"
	CodeAuthUserBanned          = "M0001009"
	CodeAuthAccountLocked       = "M0001010"
	CodeAuthRegisterFailed      = "M0001011"
	CodeAuthLogoutFailed        = "M0001012"
	CodeAuthPasswordResetFailed = "M0001013"
	CodeAuthEmailSendFailed     = "M0001014"
	CodeAuthInvalidActionToken  = "M0001015"
	CodeAuthInvalidMFA          = "M0001016"
)

// ── Session (PP=00, CC=02) ──────────────────────────────────────────────

const (
	CodeSessionNotFound     = "M0002001"
	CodeSessionNoSIDInToken = "M0002002"
)

// ── RBAC (PP=00, CC=03) ────────────────────────────────────────────────

const (
	CodeRBACCreateRoleFailed       = "M0003001"
	CodeRBACCreatePermissionFailed = "M0003002"
	CodeRBACAssignFailed           = "M0003003"
)

// ── MFA (PP=00, CC=04) ─────────────────────────────────────────────────

const (
	CodeMFASetupFailed   = "M0004001"
	CodeMFAEnableFailed  = "M0004002"
	CodeMFADisableFailed = "M0004003"
)

// ── OAuth (PP=00, CC=05) ───────────────────────────────────────────────

const (
	CodeOAuthStateInvalid  = "M0005001"
	CodeOAuthExchangeFail  = "M0005002"
	CodeOAuthUserFail      = "M0005003"
	CodeOAuthNotConfigured = "M0005004"
)
