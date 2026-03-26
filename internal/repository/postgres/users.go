package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tienh/authsvc/internal/repository"
)

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		insert into users (email, password_hash)
		values ($1, $2)
		returning id
	`, email, passwordHash).Scan(&id)
	return id, err
}

func (r *UserRepo) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		insert into users (email, password_hash, password_login_enabled)
		values ($1, $2, false)
		returning id
	`, email, passwordHash).Scan(&id)
	return id, err
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (repository.UserDTO, error) {
	var u repository.UserDTO
	err := r.db.QueryRow(ctx, `
		select id, email, password_hash, password_login_enabled, token_version, created_at, updated_at
		from users
		where email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordLoginEnabled, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.UserDTO, error) {
	var u repository.UserDTO
	err := r.db.QueryRow(ctx, `
		select id, email, password_hash, password_login_enabled, token_version, created_at, updated_at
		from users
		where id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.PasswordLoginEnabled, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepo) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		update users
		set token_version = token_version + 1,
		    updated_at = now()
		where id = $1
	`, userID)
	return err
}
