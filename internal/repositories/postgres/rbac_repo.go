package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RBACRepo struct {
	db *pgxpool.Pool
}

func NewRBACRepo(db *pgxpool.Pool) *RBACRepo {
	return &RBACRepo{db: db}
}

func (r *RBACRepo) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO roles (name) VALUES ($1)
		RETURNING id
	`, name).Scan(&id)
	return id, err
}

func (r *RBACRepo) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		INSERT INTO permissions (name) VALUES ($1)
		RETURNING id
	`, name).Scan(&id)
	return id, err
}

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
	_, err := br.Exec()
	return err
}

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

