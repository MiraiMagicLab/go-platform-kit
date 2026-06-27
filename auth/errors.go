package auth

import "github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"

var (
	ErrInvalidCredentials = domain.ErrInvalidCredentials
	ErrInvalidRefresh     = domain.ErrInvalidRefresh
	ErrSessionNotFound    = domain.ErrSessionNotFound
)

type (
	ErrAccountLocked    = domain.ErrAccountLocked
	ErrUserBanned       = domain.ErrUserBanned
	ErrEmailNotVerified = domain.ErrEmailNotVerified
	ErrMFARequired      = domain.ErrMFARequired
)
