package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id
	`, email, passwordHash).Scan(&id)
	return id, err
}

func (r *UserRepo) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, password_login_enabled)
		VALUES ($1, $2, false)
		RETURNING id
	`, email, passwordHash).Scan(&id)
	return id, err
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (UserDTO, error) {
	var u UserDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, created_at, updated_at
		FROM users
		WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (UserDTO, error) {
	var u UserDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepo) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET token_version = token_version + 1,
		    updated_at = NOW()
		WHERE id = $1
	`, userID)
	return err
}

func (r *UserRepo) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET password_hash = $2,
		    updated_at = NOW()
		WHERE id = $1
	`, userID, passwordHash)
	return err
}

func (r *UserRepo) SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET email_verified = $2,
		    updated_at = NOW()
		WHERE id = $1
	`, userID, verified)
	return err
}

func (r *UserRepo) SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET banned_until = $2,
		    ban_reason = NULLIF($3, ''),
		    updated_at = NOW()
		WHERE id = $1
	`, userID, bannedUntil, reason)
	return err
}

