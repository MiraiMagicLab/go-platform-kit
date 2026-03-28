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
		insert into roles (name) values ($1)
		returning id
	`, name).Scan(&id)
	return id, err
}

func (r *RBACRepo) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx, `
		insert into permissions (name) values ($1)
		returning id
	`, name).Scan(&id)
	return id, err
}

func (r *RBACRepo) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	batch := &pgx.Batch{}
	for _, pid := range permissionIDs {
		batch.Queue(`
			insert into role_permissions (role_id, permission_id)
			values ($1, $2)
			on conflict do nothing
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
			insert into user_roles (user_id, role_id)
			values ($1, $2)
			on conflict do nothing
		`, userID, rid)
	}
	br := r.db.SendBatch(ctx, batch)
	defer br.Close()
	_, err := br.Exec()
	return err
}

func (r *RBACRepo) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		select distinct p.name
		from permissions p
		join role_permissions rp on rp.permission_id = p.id
		join user_roles ur on ur.role_id = rp.role_id
		where ur.user_id = $1
		order by p.name
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
		select r.name
		from roles r
		join user_roles ur on ur.role_id = r.id
		where ur.user_id = $1
		order by r.name
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

