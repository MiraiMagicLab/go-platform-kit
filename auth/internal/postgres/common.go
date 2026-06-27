package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

func NewStore(db *pgxpool.Pool) ports.Store {
	return ports.Store{
		Users:        NewUserRepo(db),
		RefreshToken: NewRefreshTokenRepo(db),
		Sessions:     NewSessionsRepo(db),
		RBAC:         NewRBACRepo(db),
		Identity:     NewIdentityRepo(db),
		MFA:          NewMFARepo(db),
		Audit:        NewAuditRepo(db),
		EmailToken:   NewEmailTokenRepo(db),
	}
}
