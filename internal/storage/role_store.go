package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Role hierarchy levels (higher = more privilege).
var roleLevel = map[string]int{
	"member": 0,
	"admin":  1,
	"owner":  2,
}

// RoleStore provides tenant role operations.
type RoleStore struct {
	DB *DB
}

// NewRoleStore returns a new RoleStore.
func NewRoleStore(db *DB) *RoleStore {
	return &RoleStore{DB: db}
}

// AssignRole assigns or updates a role for a user on a tenant.
func (s *RoleStore) AssignRole(ctx context.Context, userID, tenantID uuid.UUID, role string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO tenant_roles (user_id, tenant_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = $3`,
		userID, tenantID, role,
	)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

// GetRole returns the role for a user on a tenant.
// Returns "" if no role exists.
func (s *RoleStore) GetRole(ctx context.Context, userID, tenantID uuid.UUID) (string, error) {
	var role string
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT role FROM tenant_roles WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get role: %w", err)
	}
	return role, nil
}

// HasRole checks if a user has at least the given minimum role on a tenant.
func (s *RoleStore) HasRole(ctx context.Context, userID, tenantID uuid.UUID, minRole string) (bool, error) {
	role, err := s.GetRole(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	if role == "" {
		return false, nil
	}
	return roleLevel[role] >= roleLevel[minRole], nil
}

// ListRolesForTenant returns all roles for a tenant.
func (s *RoleStore) ListRolesForTenant(ctx context.Context, tenantID uuid.UUID) ([]TenantRole, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, user_id, tenant_id, role, created_at
		 FROM tenant_roles WHERE tenant_id = $1 ORDER BY created_at`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles for tenant: %w", err)
	}
	defer rows.Close()

	var roles []TenantRole
	for rows.Next() {
		var r TenantRole
		if err := rows.Scan(&r.ID, &r.UserID, &r.TenantID, &r.Role, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// ListRolesForUser returns all roles for a user across all tenants.
func (s *RoleStore) ListRolesForUser(ctx context.Context, userID uuid.UUID) ([]TenantRole, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, user_id, tenant_id, role, created_at
		 FROM tenant_roles WHERE user_id = $1 ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list roles for user: %w", err)
	}
	defer rows.Close()

	var roles []TenantRole
	for rows.Next() {
		var r TenantRole
		if err := rows.Scan(&r.ID, &r.UserID, &r.TenantID, &r.Role, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// RemoveRole removes a user's role on a tenant.
func (s *RoleStore) RemoveRole(ctx context.Context, userID, tenantID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM tenant_roles WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("remove role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role not found for user %s on tenant %s", userID, tenantID)
	}
	return nil
}
