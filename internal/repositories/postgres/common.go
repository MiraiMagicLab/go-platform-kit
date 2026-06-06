package postgres

import "github.com/jackc/pgx/v5/pgxpool"

type Repos struct {
	User          *UserRepo
	RefreshToken  *RefreshTokenRepo
	Sessions      *SessionsRepo
	RBAC          *RBACRepo
	Identity      *IdentityRepo
	MFA           *MFARepo
	Audit         *AuditRepo
	EmailToken    *EmailTokenRepo
}

func NewRepos(db *pgxpool.Pool) *Repos {
	return &Repos{
		User:          NewUserRepo(db),
		RefreshToken:  NewRefreshTokenRepo(db),
		Sessions:      NewSessionsRepo(db),
		RBAC:          NewRBACRepo(db),
		Identity:      NewIdentityRepo(db),
		MFA:           NewMFARepo(db),
		Audit:         NewAuditRepo(db),
		EmailToken:    NewEmailTokenRepo(db),
	}
}

