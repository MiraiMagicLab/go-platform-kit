package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

var _ ports.RBACRepository = (*RBACRepo)(nil)

// RBACRepo provides PostgreSQL-backed persistence for roles, permissions, and their assignments.
type RBACRepo struct {
	db *pgxpool.Pool
}

// NewRBACRepo returns an RBACRepo backed by the given connection pool.
func NewRBACRepo(db *pgxpool.Pool) *RBACRepo {
	return &RBACRepo{db: db}
}

// CreateRole inserts a new role and returns its generated ID.
func (r *RBACRepo) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO roles (name) VALUES ($1)
		RETURNING id
	`, name).Scan(&id)
	return id, err
}

// CreatePermission inserts a new permission and returns its generated ID.
func (r *RBACRepo) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO permissions (name) VALUES ($1)
		RETURNING id
	`, name).Scan(&id)
	return id, err
}

// AssignPermissionsToRole batch-inserts permission assignments for the given role.
// Duplicate assignments are silently ignored.
func (r *RBACRepo) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	batch := &pgx.Batch{}
	for _, pid := range permissionIDs {
		batch.Queue(`
			INSERT INTO role_permissions (role_id, permission_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, roleID, pid)
	}
	br := r.db.SendBatch(ctx, batch)
	defer br.Close()
	for range permissionIDs {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return nil
}

// AssignRolesToUser batch-inserts role assignments for the given user.
// Duplicate assignments are silently ignored.
func (r *RBACRepo) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	batch := &pgx.Batch{}
	for _, rid := range roleIDs {
		batch.Queue(`
			INSERT INTO user_roles (user_id, role_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, userID, rid)
	}
	br := r.db.SendBatch(ctx, batch)
	defer br.Close()
	_, err := br.Exec()
	return err
}

// ListUserPermissions returns the distinct set of permission names assigned to the given user through their roles.
func (r *RBACRepo) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = $1
		ORDER BY p.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ListUserIDsByRole returns all user IDs that have the given role assigned.
func (r *RBACRepo) ListUserIDsByRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.db.Query(ctx, `
		SELECT user_id FROM user_roles WHERE role_id = $1
	`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListUserRoles returns the names of all roles assigned to the given user.
func (r *RBACRepo) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// GetRoleIDByName returns the role ID for the given unique role name.
func (r *RBACRepo) GetRoleIDByName(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&id)
	return id, err
}
