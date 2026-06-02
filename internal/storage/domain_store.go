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

// GetTenantByStripeSubscription finds the tenant backed by a given Stripe
// subscription id (ADR-010), used by the seat-change webhook re-sync.
func (s *DomainStore) GetTenantByStripeSubscription(ctx context.Context, subID string) (*Tenant, error) {
	t := &Tenant{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT tenant_id, domain, created_at, mx_verified,
			dkim_private_key_encrypted, COALESCE(dkim_public_key, ''), COALESCE(dkim_selector, ''),
			dkim_rsa_private_key_encrypted, COALESCE(dkim_rsa_public_key, ''), COALESCE(dkim_rsa_selector, ''),
			COALESCE(tier, 'mail'), owner_user_id, verified,
			COALESCE(dkim_pool_selector, '')
		 FROM tenants WHERE stripe_subscription_id = $1`, subID,
	).Scan(
		&t.TenantID, &t.Domain, &t.CreatedAt, &t.MXVerified,
		&t.DKIMPrivateKeyEncrypted, &t.DKIMPublicKey, &t.DKIMSelector,
		&t.DKIMRSAPrivateKeyEncrypted, &t.DKIMRSAPublicKey, &t.DKIMRSASelector,
		&t.Tier, &t.OwnerUserID, &t.Verified,
		&t.DKIMPoolSelector,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tenant not found for subscription: %s", subID)
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant by subscription: %w", err)
	}
	return t, nil
}

// GetTenantStripeSubscription returns the tenant's Stripe subscription id (or
// "" if none). Lightweight lookup so seat/storage handlers can find the
// subscription without widening the main tenant scan.
func (s *DomainStore) GetTenantStripeSubscription(ctx context.Context, tenantID uuid.UUID) (string, error) {
	var subID string
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(stripe_subscription_id, '') FROM tenants WHERE tenant_id = $1`,
		tenantID,
	).Scan(&subID)
	if err != nil {
		return "", fmt.Errorf("get tenant stripe subscription: %w", err)
	}
	return subID, nil
}

// CreateAlias adds an alias address that delivers into targetUserID's mailbox.
func (s *DomainStore) CreateAlias(ctx context.Context, tenantID uuid.UUID, address string, targetUserID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO aliases (alias_id, tenant_id, address, target_user_id)
		 VALUES (gen_random_uuid(), $1, $2, $3)`,
		tenantID, address, targetUserID,
	)
	if err != nil {
		return fmt.Errorf("create alias: %w", err)
	}
	return nil
}

// ListAliases returns all aliases for a tenant.
func (s *DomainStore) ListAliases(ctx context.Context, tenantID uuid.UUID) ([]Alias, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT alias_id, tenant_id, address, target_user_id, created_at
		 FROM aliases WHERE tenant_id = $1 ORDER BY address`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.AliasID, &a.TenantID, &a.Address, &a.TargetUserID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAlias removes an alias by address within a tenant.
func (s *DomainStore) DeleteAlias(ctx context.Context, tenantID uuid.UUID, address string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM aliases WHERE tenant_id = $1 AND address = $2`, tenantID, address,
	)
	if err != nil {
		return fmt.Errorf("delete alias: %w", err)
	}
	return nil
}

// SetCatchAll sets (or clears, when userID is nil) a tenant's catch-all mailbox.
func (s *DomainStore) SetCatchAll(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET catch_all_user_id = $2 WHERE tenant_id = $1`, tenantID, userID,
	)
	if err != nil {
		return fmt.Errorf("set catch-all: %w", err)
	}
	return nil
}

// ListTenants returns all tenants.
// ListUnverifiedOwnedTenants returns custom-domain (owner-set) tenants whose
// ownership hasn't been verified yet. Used by the background re-verification
// sweep. Only the fields needed for the ownership check are populated.
func (s *DomainStore) ListUnverifiedOwnedTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT tenant_id, domain, owner_user_id
		 FROM tenants WHERE owner_user_id IS NOT NULL AND verified = false`)
	if err != nil {
		return nil, fmt.Errorf("list unverified owned tenants: %w", err)
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		t := &Tenant{Verified: false}
		if err := rows.Scan(&t.TenantID, &t.Domain, &t.OwnerUserID); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

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

// UpdateTenantStripeSubscription records the Stripe subscription ID backing a
// custom domain (ADR-010), so later per-seat / storage mutations can find and
// modify the subscription. No-op-safe if the tenant doesn't exist.
func (s *DomainStore) UpdateTenantStripeSubscription(ctx context.Context, tenantID uuid.UUID, subID string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE tenants SET stripe_subscription_id = $2 WHERE tenant_id = $1`,
		tenantID, subID,
	)
	if err != nil {
		return fmt.Errorf("update tenant stripe subscription: %w", err)
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

// GetReclaimChallenge returns the most recent non-expired reclaim challenge for
// a domain (status='reclaim'), used by the org-reclaim handshake to let the real
// owner take over an unverified squat by proving DNS control. Returns an error
// if none exists.
func (s *DomainStore) GetReclaimChallenge(ctx context.Context, domain string) (*DomainVerification, error) {
	v := &DomainVerification{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT verification_id, tenant_id, domain, challenge_token, status, created_at, verified_at, expires_at
		 FROM domain_verifications
		 WHERE domain = $1 AND status = 'reclaim' AND expires_at > now()
		 ORDER BY created_at DESC LIMIT 1`, domain,
	).Scan(
		&v.VerificationID, &v.TenantID, &v.Domain, &v.ChallengeToken,
		&v.Status, &v.CreatedAt, &v.VerifiedAt, &v.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no reclaim challenge for domain: %s", domain)
	}
	if err != nil {
		return nil, fmt.Errorf("get reclaim challenge: %w", err)
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
