package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"

type (
	User             = domain.User
	Session          = domain.Session
	SessionListInfo  = domain.SessionListInfo
	ClientMeta       = domain.ClientMeta
	RefreshToken     = domain.RefreshToken
	RotateResult     = domain.RotateResult
	AccessTokenMeta  = domain.AccessTokenMeta
	Role             = domain.Role
	Permission       = domain.Permission
	MFAConfig        = domain.MFAConfig
	MFASetup         = domain.MFASetup
	OAuthIdentity    = domain.OAuthIdentity
	AuditEntry       = domain.AuditEntry
	EmailActionToken = domain.EmailActionToken
)
