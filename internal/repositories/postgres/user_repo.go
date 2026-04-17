package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	db *pgxpool.Pool
}

type ListUsersFilter struct {
	Search               string
	Email                string
	EmailVerified        *bool
	PasswordLoginEnabled *bool
	IsBanned             *bool
	CreatedFrom          *time.Time
	CreatedTo            *time.Time
	SortBy               string
	SortOrder            string
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

func (r *UserRepo) ListUsers(ctx context.Context, page, pageSize int, f ListUsersFilter) ([]UserDTO, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize

	sortBy := "created_at"
	switch f.SortBy {
	case "email", "created_at", "updated_at":
		sortBy = f.SortBy
	}
	sortOrder := "DESC"
	if strings.EqualFold(f.SortOrder, "asc") {
		sortOrder = "ASC"
	}

	var conditions []string
	var args []any
	if f.Search != "" {
		args = append(args, "%"+strings.ToLower(strings.TrimSpace(f.Search))+"%")
		conditions = append(conditions, fmt.Sprintf("LOWER(email) LIKE $%d", len(args)))
	}
	if f.Email != "" {
		args = append(args, strings.TrimSpace(f.Email))
		conditions = append(conditions, fmt.Sprintf("email = $%d", len(args)))
	}
	if f.EmailVerified != nil {
		args = append(args, *f.EmailVerified)
		conditions = append(conditions, fmt.Sprintf("email_verified = $%d", len(args)))
	}
	if f.PasswordLoginEnabled != nil {
		args = append(args, *f.PasswordLoginEnabled)
		conditions = append(conditions, fmt.Sprintf("password_login_enabled = $%d", len(args)))
	}
	if f.IsBanned != nil {
		if *f.IsBanned {
			conditions = append(conditions, "banned_until IS NOT NULL AND banned_until > NOW()")
		} else {
			conditions = append(conditions, "(banned_until IS NULL OR banned_until <= NOW())")
		}
	}
	if f.CreatedFrom != nil {
		args = append(args, *f.CreatedFrom)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.CreatedTo != nil {
		args = append(args, *f.CreatedTo)
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM users" + whereClause
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, pageSize, offset)
	dataQuery := fmt.Sprintf(`
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, created_at, updated_at
		FROM users
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortBy, sortOrder, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []UserDTO
	for rows.Next() {
		var u UserDTO
		err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}

	return users, total, nil
}
