package postgres

import "github.com/jackc/pgx/v5/pgxpool"

type Repositories struct {
	Users         *UserRepo
	RefreshTokens *RefreshTokenRepo
	RBAC          *RBACRepo
	Identities    *IdentityRepo
	MFA           *MFARepo
	Audit         *AuditRepo
	EmailTokens   *EmailTokenRepo
}

func NewRepositories(db *pgxpool.Pool) *Repositories {
	return &Repositories{
		Users:         NewUserRepo(db),
		RefreshTokens: NewRefreshTokenRepo(db),
		RBAC:          NewRBACRepo(db),
		Identities:    NewIdentityRepo(db),
		MFA:           NewMFARepo(db),
		Audit:         NewAuditRepo(db),
		EmailTokens:   NewEmailTokenRepo(db),
	}
}

