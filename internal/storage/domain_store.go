package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DomainStore wraps DB and provides domain/tenant-related database operations.
type DomainStore struct {
	DB *DB
}

// NewDomainStore returns a new DomainStore backed by the given DB.
func NewDomainStore(db *DB) *DomainStore {
	return &DomainStore{DB: db}
}

// CreateTenant inserts a new tenant into the tenants table.
func (s *DomainStore) CreateTenant(ctx context.Context, tenant *Tenant) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO tenants (tenant_id, domain, mx_verified, dkim_private_key_encrypted, dkim_public_key, dkim_selector, tier, owner_user_id, verified)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		tenant.TenantID, tenant.Domain, tenant.MXVerified,
		tenant.DKIMPrivateKeyEncrypted, tenant.DKIMPublicKey, tenant.DKIMSelector,
		tenant.Tier, tenant.OwnerUserID, tenant.Verified,
	)
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	return nil
}

// GetTenant retrieves a tenant by its ID.
func (s *DomainStore) GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT tenant_id, domain, created_at, mx_verified,
			dkim_private_key_encrypted, COALESCE(dkim_public_key, ''), COALESCE(dkim_selector, ''),
			dkim_rsa_private_key_encrypted, COALESCE(dkim_rsa_public_key, ''), COALESCE(dkim_rsa_selector, ''),
			COALESCE(tier, 'mail'), owner_user_id, verified,
			COALESCE(dkim_pool_selector, '')
		 FROM tenants WHERE tenant_id = $1`, tenantID,
	).Scan(
		&t.TenantID, &t.Domain, &t.CreatedAt, &t.MXVerified,
		&t.DKIMPrivateKeyEncrypted, &t.DKIMPublicKey, &t.DKIMSelector,
		&t.DKIMRSAPrivateKeyEncrypted, &t.DKIMRSAPublicKey, &t.DKIMRSASelector,
		&t.Tier, &t.OwnerUserID, &t.Verified,
		&t.DKIMPoolSelector,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

// GetTenantByDomain retrieves a tenant by its domain name.
func (s *DomainStore) GetTenantByDomain(ctx context.Context, domain string) (*Tenant, error) {
	t := &Tenant{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT tenant_id, domain, created_at, mx_verified,
			dkim_private_key_encrypted, COALESCE(dkim_public_key, ''), COALESCE(dkim_selector, ''),
			dkim_rsa_private_key_encrypted, COALESCE(dkim_rsa_public_key, ''), COALESCE(dkim_rsa_selector, ''),
			COALESCE(tier, 'mail'), owner_user_id, verified,
			COALESCE(dkim_pool_selector, '')
		 FROM tenants WHERE domain = $1`, domain,
	).Scan(
		&t.TenantID, &t.Domain, &t.CreatedAt, &t.MXVerified,
		&t.DKIMPrivateKeyEncrypted, &t.DKIMPublicKey, &t.DKIMSelector,
		&t.DKIMRSAPrivateKeyEncrypted, &t.DKIMRSAPublicKey, &t.DKIMRSASelector,
		&t.Tier, &t.OwnerUserID, &t.Verified,
		&t.DKIMPoolSelector,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tenant not found for domain: %s", domain)
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant by domain: %w", err)
	}
	return t, nil
}

// ListTenants returns all tenants.
func (s *DomainStore) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT tenant_id, domain, created_at, mx_verified,
			dkim_private_key_encrypted, COALESCE(dkim_public_key, ''), COALESCE(dkim_selector, ''),
			dkim_rsa_private_key_encrypted, COALESCE(dkim_rsa_public_key, ''), COALESCE(dkim_rsa_selector, ''),
			COALESCE(tier, 'mail'), owner_user_id, verified,
			COALESCE(dkim_pool_selector, '')
		 FROM tenants ORDER BY created_at LIMIT 10000`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		t := &Tenant{}
		if err := rows.Scan(
			&t.TenantID, &t.Domain, &t.CreatedAt, &t.MXVerified,
			&t.DKIMPrivateKeyEncrypted, &t.DKIMPublicKey, &t.DKIMSelector,
			&t.DKIMRSAPrivateKeyEncrypted, &t.DKIMRSAPublicKey, &t.DKIMRSASelector,
			&t.Tier, &t.OwnerUserID, &t.Verified,
			&t.DKIMPoolSelector,
		); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return tenants, nil
}

// SetTenantDKIMPoolSelector flips a tenant onto (or off of) the
// shared DKIM pool. Empty string puts them back on the legacy
// per-tenant key columns. Per ADR-007.
func (s *DomainStore) SetTenantDKIMPoolSelector(ctx context.Context, tenantID uuid.UUID, selector string) error {
	var v interface{}
	if selector == "" {
		v = nil
	} else {
		v = selector
	}
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET dkim_pool_selector = $2 WHERE tenant_id = $1`,
		tenantID, v,
	)
	if err != nil {
		return fmt.Errorf("update dkim_pool_selector: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// UpdateTenantMXVerified updates the mx_verified flag for a tenant.
func (s *DomainStore) UpdateTenantMXVerified(ctx context.Context, tenantID uuid.UUID, verified bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET mx_verified = $2 WHERE tenant_id = $1`,
		tenantID, verified,
	)
	if err != nil {
		return fmt.Errorf("update tenant mx_verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// DeleteTenant deletes a tenant by its ID.
func (s *DomainStore) DeleteTenant(ctx context.Context, tenantID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx, `DELETE FROM tenants WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// UpdateTenantTier updates the tier for a tenant.
func (s *DomainStore) UpdateTenantTier(ctx context.Context, tenantID uuid.UUID, tier string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET tier = $2 WHERE tenant_id = $1`,
		tenantID, tier,
	)
	if err != nil {
		return fmt.Errorf("update tenant tier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// UpdateTenantOwner sets the owner user ID for a tenant.
func (s *DomainStore) UpdateTenantOwner(ctx context.Context, tenantID uuid.UUID, ownerID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET owner_user_id = $2 WHERE tenant_id = $1`,
		tenantID, ownerID,
	)
	if err != nil {
		return fmt.Errorf("update tenant owner: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// UpdateTenantVerified sets the verified flag for a tenant.
func (s *DomainStore) UpdateTenantVerified(ctx context.Context, tenantID uuid.UUID, verified bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET verified = $2 WHERE tenant_id = $1`,
		tenantID, verified,
	)
	if err != nil {
		return fmt.Errorf("update tenant verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// CreateVerification inserts a new domain verification challenge.
func (s *DomainStore) CreateVerification(ctx context.Context, v *DomainVerification) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO domain_verifications (verification_id, tenant_id, domain, challenge_token, status, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		v.VerificationID, v.TenantID, v.Domain, v.ChallengeToken, v.Status, v.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create verification: %w", err)
	}
	return nil
}

// GetPendingVerification returns the most recent pending verification for a domain.
func (s *DomainStore) GetPendingVerification(ctx context.Context, domain string) (*DomainVerification, error) {
	v := &DomainVerification{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT verification_id, tenant_id, domain, challenge_token, status, created_at, verified_at, expires_at
		 FROM domain_verifications
		 WHERE domain = $1 AND status = 'pending' AND expires_at > now()
		 ORDER BY created_at DESC LIMIT 1`, domain,
	).Scan(
		&v.VerificationID, &v.TenantID, &v.Domain, &v.ChallengeToken,
		&v.Status, &v.CreatedAt, &v.VerifiedAt, &v.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no pending verification for domain: %s", domain)
	}
	if err != nil {
		return nil, fmt.Errorf("get pending verification: %w", err)
	}
	return v, nil
}

// MarkVerified marks a domain verification as verified.
func (s *DomainStore) MarkVerified(ctx context.Context, verificationID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE domain_verifications SET status = 'verified', verified_at = now()
		 WHERE verification_id = $1`,
		verificationID,
	)
	if err != nil {
		return fmt.Errorf("mark verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("verification not found: %s", verificationID)
	}
	return nil
}

// UpdateTenantDKIM updates the DKIM key material for a tenant.
func (s *DomainStore) UpdateTenantDKIM(ctx context.Context, tenantID uuid.UUID, encryptedPrivKey []byte, pubKey, selector string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET dkim_private_key_encrypted = $2, dkim_public_key = $3, dkim_selector = $4
		 WHERE tenant_id = $1`,
		tenantID, encryptedPrivKey, pubKey, selector,
	)
	if err != nil {
		return fmt.Errorf("update tenant dkim: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}

// UpdateTenantRSADKIM updates the RSA DKIM key for a tenant.
func (s *DomainStore) UpdateTenantRSADKIM(ctx context.Context, tenantID uuid.UUID, encryptedPrivKey []byte, pubKey, selector string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET dkim_rsa_private_key_encrypted = $2, dkim_rsa_public_key = $3, dkim_rsa_selector = $4
		 WHERE tenant_id = $1`,
		tenantID, encryptedPrivKey, pubKey, selector,
	)
	if err != nil {
		return fmt.Errorf("update tenant rsa dkim: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	return nil
}
