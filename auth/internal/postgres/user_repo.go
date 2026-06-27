package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

var _ ports.UserRepository = (*UserRepo)(nil)

// UserRepo provides PostgreSQL-backed persistence for user accounts.
type UserRepo struct {
	db *pgxpool.Pool
}

// NewUserRepo returns a UserRepo backed by the given connection pool.
func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

// Create inserts a new user with the given email and password hash.
// It returns the generated user ID.
func (r *UserRepo) Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id
	`, email, passwordHash).Scan(&id)
	return id, err
}

// CreateOAuthUser inserts a new OAuth-provisioned user with password login disabled.
// It returns the generated user ID.
func (r *UserRepo) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, password_login_enabled)
		VALUES ($1, $2, false)
		RETURNING id
	`, email, passwordHash).Scan(&id)
	return id, err
}

// GetByEmail returns the user with the given email address.
// It excludes soft-deleted users.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	dto, err := r.getByEmail(ctx, email)
	if err != nil {
		return domain.User{}, err
	}
	return dtoToUser(dto), nil
}

// GetByID returns the user with the given ID.
// It excludes soft-deleted users.
func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	dto, err := r.getByID(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	return dtoToUser(dto), nil
}

func (r *UserRepo) getByEmail(ctx context.Context, email string) (UserDTO, error) {
	var u UserDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, failed_login_count, locked_until, deleted_at, created_at, updated_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.FailedLoginCount, &u.LockedUntil, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *UserRepo) getByID(ctx context.Context, id uuid.UUID) (UserDTO, error) {
	var u UserDTO
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, failed_login_count, locked_until, deleted_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.FailedLoginCount, &u.LockedUntil, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// IncrementTokenVersion atomically increments the user's token version,
// invalidating all previously issued refresh tokens for that user.
func (r *UserRepo) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET token_version = token_version + 1,
		    updated_at = NOW()
		WHERE id = $1
	`, userID)
	return err
}

// SetPassword updates the password hash for the given user.
func (r *UserRepo) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1 AND deleted_at IS NULL
	`, userID, passwordHash)
	return err
}

// SetEmailVerified sets the email verification status for the given user.
func (r *UserRepo) SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET email_verified = $2
		WHERE id = $1 AND deleted_at IS NULL
	`, userID, verified)
	return err
}

// SetBan applies or lifts a ban on the given user.
// A nil bannedUntil lifts the ban. It also resets failed login counters and lockouts.
func (r *UserRepo) SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET banned_until = $2,
		    ban_reason = NULLIF($3, ''),
		    failed_login_count = 0,
		    locked_until = NULL
		WHERE id = $1 AND deleted_at IS NULL
	`, userID, bannedUntil, reason)
	return err
}

// ListUsers returns a paginated, filtered list of users and the total count matching the filter.
// Page is clamped to a minimum of 1, pageSize to [1, 100].
func (r *UserRepo) ListUsers(ctx context.Context, page, pageSize int, f ports.ListUsersFilter) ([]domain.User, int, error) {
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
		SELECT id, email, password_hash, email_verified, password_login_enabled, banned_until, ban_reason, token_version, failed_login_count, locked_until, deleted_at, created_at, updated_at
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

	var dtos []UserDTO
	for rows.Next() {
		var u UserDTO
		err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.PasswordLoginEnabled, &u.BannedUntil, &u.BanReason, &u.TokenVersion, &u.FailedLoginCount, &u.LockedUntil, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return nil, 0, err
		}
		dtos = append(dtos, u)
	}

	users := make([]domain.User, len(dtos))
	for i, dto := range dtos {
		users[i] = dtoToUser(dto)
	}
	return users, total, nil
}

func dtoToUser(dto UserDTO) domain.User {
	return domain.User{
		ID:                   dto.ID,
		Email:                dto.Email,
		PasswordHash:         dto.PasswordHash,
		EmailVerified:        dto.EmailVerified,
		PasswordLoginEnabled: dto.PasswordLoginEnabled,
		BannedUntil:          dto.BannedUntil,
		BanReason:            dto.BanReason,
		TokenVersion:         dto.TokenVersion,
		FailedLoginCount:     dto.FailedLoginCount,
		LockedUntil:          dto.LockedUntil,
		DeletedAt:            dto.DeletedAt,
		CreatedAt:            dto.CreatedAt,
		UpdatedAt:            dto.UpdatedAt,
	}
}

// IncrementFailedLogin atomically increments the failed login counter for the given user.
func (r *UserRepo) IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET failed_login_count = failed_login_count + 1
		WHERE id = $1 AND deleted_at IS NULL
	`, userID)
	return err
}

// ResetFailedLogin clears the failed login counter and removes any account lockout for the given user.
func (r *UserRepo) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET failed_login_count = 0, locked_until = NULL
		WHERE id = $1 AND deleted_at IS NULL
	`, userID)
	return err
}

// SetLock applies a temporary account lockout to the given user until the specified time.
func (r *UserRepo) SetLock(ctx context.Context, userID uuid.UUID, until time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET locked_until = $2
		WHERE id = $1 AND deleted_at IS NULL
	`, userID, until)
	return err
}

// SoftDelete marks the user as deleted, anonymizes their email, and invalidates all tokens.
func (r *UserRepo) SoftDelete(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users
		SET deleted_at = NOW(),
		    email = email || '_deleted_' || NOW()::text,
		    token_version = token_version + 1
		WHERE id = $1 AND deleted_at IS NULL
	`, userID)
	return err
}
