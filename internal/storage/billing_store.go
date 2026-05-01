package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BillingStore provides billing and tier-limit operations.
type BillingStore struct {
	DB *DB
}

// NewBillingStore returns a new BillingStore.
func NewBillingStore(db *DB) *BillingStore {
	return &BillingStore{DB: db}
}

// GetTierLimits returns the limits for a given tier.
func (s *BillingStore) GetTierLimits(ctx context.Context, tier string) (*TierLimits, error) {
	t := &TierLimits{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT tier, max_mailboxes, max_storage_bytes, max_custom_domains, price_cents
		 FROM tier_limits WHERE tier = $1`, tier,
	).Scan(&t.Tier, &t.MaxMailboxes, &t.MaxStorageBytes, &t.MaxCustomDomains, &t.PriceCents)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tier not found: %s", tier)
	}
	if err != nil {
		return nil, fmt.Errorf("get tier limits: %w", err)
	}
	return t, nil
}

// ListTierLimits returns all tier limits ordered by price.
func (s *BillingStore) ListTierLimits(ctx context.Context) ([]TierLimits, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT tier, max_mailboxes, max_storage_bytes, max_custom_domains, price_cents
		 FROM tier_limits ORDER BY price_cents`)
	if err != nil {
		return nil, fmt.Errorf("list tier limits: %w", err)
	}
	defer rows.Close()

	var tiers []TierLimits
	for rows.Next() {
		var t TierLimits
		if err := rows.Scan(&t.Tier, &t.MaxMailboxes, &t.MaxStorageBytes, &t.MaxCustomDomains, &t.PriceCents); err != nil {
			return nil, fmt.Errorf("scan tier: %w", err)
		}
		tiers = append(tiers, t)
	}
	return tiers, rows.Err()
}

// AddCredit inserts a new billing credit for a tenant.
func (s *BillingStore) AddCredit(ctx context.Context, credit *BillingCredit) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO billing_credits (credit_id, tenant_id, tier, mailbox_quota, valid_from, valid_until, token_hash, price_cents_each)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		credit.CreditID, credit.TenantID, credit.Tier, credit.MailboxQuota,
		credit.ValidFrom, credit.ValidUntil, credit.TokenHash, credit.PriceCentsEach,
	)
	if err != nil {
		return fmt.Errorf("add billing credit: %w", err)
	}
	return nil
}

// GetActiveMailboxQuota returns the total active mailbox quota for a tenant.
func (s *BillingStore) GetActiveMailboxQuota(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var total int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(mailbox_quota), 0) FROM billing_credits
		 WHERE tenant_id = $1 AND valid_from <= now() AND valid_until > now()`,
		tenantID,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("get active mailbox quota: %w", err)
	}
	return total, nil
}

// GetActiveCredits returns all active billing credits for a tenant.
func (s *BillingStore) GetActiveCredits(ctx context.Context, tenantID uuid.UUID) ([]BillingCredit, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT credit_id, tenant_id, tier, mailbox_quota, valid_from, valid_until, token_hash, price_cents_each, created_at
		 FROM billing_credits
		 WHERE tenant_id = $1 AND valid_from <= now() AND valid_until > now()
		 ORDER BY valid_until`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get active credits: %w", err)
	}
	defer rows.Close()

	var credits []BillingCredit
	for rows.Next() {
		var c BillingCredit
		if err := rows.Scan(&c.CreditID, &c.TenantID, &c.Tier, &c.MailboxQuota,
			&c.ValidFrom, &c.ValidUntil, &c.TokenHash, &c.PriceCentsEach, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan credit: %w", err)
		}
		credits = append(credits, c)
	}
	return credits, rows.Err()
}

// UpdateUserStorage atomically adds deltaBytes to a user's storage_used_bytes within a tenant.
func (s *BillingStore) UpdateUserStorage(ctx context.Context, userID, tenantID uuid.UUID, deltaBytes int64) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes + $2) WHERE user_id = $1 AND tenant_id = $3`,
		userID, deltaBytes, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update user storage: %w", err)
	}
	return nil
}

// GetUserStorage returns a user's current mail storage usage in bytes
// within a tenant. Computed live as SUM(messages.size_bytes) +
// SUM(attachments.size_bytes) — mirroring the drive store's live SUM
// pattern. The users.storage_used_bytes column is not used as a source
// of truth: no path increments it on insert, so the column is always
// stale (effectively zero), which silently broke the over-quota gates
// for both internal compose and SMTP-inbound RCPT TO. Live SUM keeps
// quota enforcement accurate without needing audit-tight increment/
// decrement on every insert/delete path.
func (s *BillingStore) GetUserStorage(ctx context.Context, userID, tenantID uuid.UUID) (int64, error) {
	var used int64
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT
			COALESCE((SELECT SUM(size_bytes) FROM messages    WHERE user_id = $1 AND tenant_id = $2), 0)
		  + COALESCE((SELECT SUM(size_bytes) FROM attachments WHERE user_id = $1 AND tenant_id = $2), 0)`,
		userID, tenantID,
	).Scan(&used)
	if err != nil {
		return 0, fmt.Errorf("get user storage: %w", err)
	}
	return used, nil
}

// CountTenantMailboxes returns the number of users (mailboxes) for a tenant.
func (s *BillingStore) CountTenantMailboxes(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1`, tenantID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count tenant mailboxes: %w", err)
	}
	return count, nil
}

// CountTenantCustomDomains returns the number of verified custom domains for a tenant's owner.
func (s *BillingStore) CountTenantCustomDomains(ctx context.Context, ownerUserID uuid.UUID) (int, error) {
	var count int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenant_roles tr
		 JOIN tenants t ON tr.tenant_id = t.tenant_id
		 WHERE tr.user_id = $1 AND tr.role = 'owner' AND t.verified = true`, ownerUserID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count custom domains: %w", err)
	}
	return count, nil
}

// GetPricingBrackets returns all pricing brackets ordered by min_mailboxes.
func (s *BillingStore) GetPricingBrackets(ctx context.Context) ([]PricingBracket, error) {
	rows, err := s.DB.Pool.Query(ctx, `SELECT min_mailboxes, max_mailboxes, price_cents FROM pricing_brackets ORDER BY min_mailboxes`)
	if err != nil {
		return nil, fmt.Errorf("get pricing brackets: %w", err)
	}
	defer rows.Close()
	var brackets []PricingBracket
	for rows.Next() {
		var b PricingBracket
		if err := rows.Scan(&b.MinMailboxes, &b.MaxMailboxes, &b.PriceCents); err != nil {
			return nil, fmt.Errorf("scan pricing bracket: %w", err)
		}
		brackets = append(brackets, b)
	}
	return brackets, rows.Err()
}

// CalculateMailboxCost computes the total monthly cost for N mailboxes using volume brackets.
func CalculateMailboxCost(count int, brackets []PricingBracket) int {
	total := 0
	remaining := count
	for _, b := range brackets {
		if remaining <= 0 {
			break
		}
		bracketSize := b.MaxMailboxes - b.MinMailboxes + 1
		inBracket := remaining
		if inBracket > bracketSize {
			inBracket = bracketSize
		}
		total += inBracket * b.PriceCents
		remaining -= inBracket
	}
	// If remaining > 0, use the last bracket's price
	if remaining > 0 && len(brackets) > 0 {
		total += remaining * brackets[len(brackets)-1].PriceCents
	}
	return total
}

// CalculateMonthlyTotal computes the monthly cost for a tenant based on mailbox count and storage addons.
func (s *BillingStore) CalculateMonthlyTotal(ctx context.Context, tenantID uuid.UUID) (totalCents int, err error) {
	count, err := s.CountTenantMailboxes(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	brackets, err := s.GetPricingBrackets(ctx)
	if err != nil {
		return 0, err
	}
	totalCents = CalculateMailboxCost(count, brackets)

	// Add storage addon costs
	var storageCents int
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(blocks * price_cents), 0) FROM storage_addons WHERE tenant_id = $1 AND valid_from <= now() AND valid_until > now()`,
		tenantID).Scan(&storageCents)
	if err != nil {
		return 0, err
	}
	totalCents += storageCents
	return totalCents, nil
}

// GetActiveStorageAddons returns active storage add-ons for a tenant.
func (s *BillingStore) GetActiveStorageAddons(ctx context.Context, tenantID uuid.UUID) ([]StorageAddon, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT addon_id, tenant_id, blocks, price_cents, valid_from, valid_until, created_at FROM storage_addons WHERE tenant_id = $1 AND valid_from <= now() AND valid_until > now() ORDER BY created_at`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("get active storage addons: %w", err)
	}
	defer rows.Close()
	var addons []StorageAddon
	for rows.Next() {
		var a StorageAddon
		if err := rows.Scan(&a.AddonID, &a.TenantID, &a.Blocks, &a.PriceCents, &a.ValidFrom, &a.ValidUntil, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan storage addon: %w", err)
		}
		addons = append(addons, a)
	}
	return addons, rows.Err()
}

// AddStorageAddon inserts a storage add-on for a tenant.
func (s *BillingStore) AddStorageAddon(ctx context.Context, addon *StorageAddon) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO storage_addons (addon_id, tenant_id, blocks, price_cents, valid_from, valid_until) VALUES ($1, $2, $3, $4, $5, $6)`,
		addon.AddonID, addon.TenantID, addon.Blocks, addon.PriceCents, addon.ValidFrom, addon.ValidUntil)
	if err != nil {
		return fmt.Errorf("add storage addon: %w", err)
	}
	return nil
}

// StorageBlockBytes is the size of one purchased top-up block: 10 GB
// each, sold at $1/mo (handlePersonalBilling.storage_block_price_cents).
// EffectiveStorageLimit adds users.storage_blocks * StorageBlockBytes to
// the primary's base allocation.
const StorageBlockBytes = int64(10) * 1073741824

// PrimaryBaseStorageBytes is the included storage allotment for any
// primary account, regardless of mailbox count or tenant. Per-user, not
// pooled — historically 15 GB during beta. Storage top-ups stack on top.
const PrimaryBaseStorageBytes = int64(15) * 1073741824

// FreeStorageBytes is the storage cap for tier='free' accounts. Hard cap;
// not augmentable via storage_blocks (the storage top-up product is paid-
// tier only). 100 MB is enough for ~years of casual use; the cap is the
// primary upgrade pressure point on the free tier.
const FreeStorageBytes = int64(100) * 1024 * 1024

// SetUserStorageBlocks atomically sets the user's storage_blocks count.
// Called from the POST /billing/storage handler after a successful
// Stripe subscription update, and from the webhook reconciler so external
// Stripe changes (cancellation, manual portal edits) stay synced.
func (s *BillingStore) SetUserStorageBlocks(ctx context.Context, userID uuid.UUID, blocks int) error {
	if blocks < 0 {
		return fmt.Errorf("storage_blocks cannot be negative: %d", blocks)
	}
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET storage_blocks = $2 WHERE user_id = $1`,
		userID, blocks,
	)
	if err != nil {
		return fmt.Errorf("set user storage blocks: %w", err)
	}
	return nil
}

// GetUserStorageBlocks returns the current top-up count for a user.
func (s *BillingStore) GetUserStorageBlocks(ctx context.Context, userID uuid.UUID) (int, error) {
	var blocks int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT storage_blocks FROM users WHERE user_id = $1`,
		userID,
	).Scan(&blocks)
	if err != nil {
		return 0, fmt.Errorf("get user storage blocks: %w", err)
	}
	return blocks, nil
}

// FakeIDStorageLimitBytes is the hard storage cap applied to Fake ID
// accounts: 1 GB combined across mail + drive + everything else stored
// per-user. Not augmentable via storage_addons — see EffectiveStorageLimit
// for the per-user gate that enforces this regardless of the tenant's
// pooled quota.
const FakeIDStorageLimitBytes = int64(1) * 1073741824

// EffectiveStorageLimit returns the storage cap applicable to a single
// user. Lookup order:
//   - accountType="fakeid"  → flat 1 GB (FakeIDStorageLimitBytes)
//   - tier="free"           → flat 100 MB (FreeStorageBytes)
//   - primary paid          → 15 GB base + storage_blocks * 10 GB
//
// Use this in any per-user write-time quota gate; tenant-level limits
// remain authoritative for org-tenant admin views via
// GetTenantStorageLimit.
//
// accountType: the user's account_type column ("primary" or "fakeid").
// Empty is treated as primary for back-compat.
// tier: the user's tier column ("free", "mail", "unlimited", "business",
// "enterprise"). Empty is treated as paid (back-compat with rows that
// pre-date the free tier).
func (s *BillingStore) EffectiveStorageLimit(ctx context.Context, userID uuid.UUID, accountType, tier string) (int64, error) {
	if accountType == "fakeid" {
		return FakeIDStorageLimitBytes, nil
	}
	if tier == "free" {
		return FreeStorageBytes, nil
	}
	blocks, err := s.GetUserStorageBlocks(ctx, userID)
	if err != nil {
		// Fall back to base allocation if the lookup fails — surfacing
		// 0 quota would block writes for everyone during a transient
		// PG hiccup, which is worse than slightly under-counting top-ups.
		return PrimaryBaseStorageBytes, nil
	}
	return PrimaryBaseStorageBytes + int64(blocks)*StorageBlockBytes, nil
}

// EffectiveStorageUsed returns the usage figure paired with
// EffectiveStorageLimit. Per-user for both primary and fakeid (tenant-
// wide aggregation is no longer used by the personal quota path — the
// per-user limit makes pooling impossible to enforce sensibly). Returns
// the user's own storage_used_bytes plus their driveUsed.
func (s *BillingStore) EffectiveStorageUsed(ctx context.Context, userID, tenantID uuid.UUID, _ string, driveUsed int64) (int64, error) {
	mailUsed, err := s.GetUserStorage(ctx, userID, tenantID)
	if err != nil {
		return 0, err
	}
	return mailUsed + driveUsed, nil
}

// GetTenantStorageLimit returns the total storage limit for a tenant in bytes.
// Base: 15GB per mailbox. Extra: 10GB per addon block.
func (s *BillingStore) GetTenantStorageLimit(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	count, err := s.CountTenantMailboxes(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var extraBlocks int
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(blocks), 0) FROM storage_addons WHERE tenant_id = $1 AND valid_from <= now() AND valid_until > now()`,
		tenantID).Scan(&extraBlocks)
	if err != nil {
		return 0, err
	}
	const gb = int64(1073741824)
	return int64(count)*15*gb + int64(extraBlocks)*10*gb, nil
}

// GetTenantStorageUsed returns total storage used across all users in a tenant.
func (s *BillingStore) GetTenantStorageUsed(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var used int64
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(storage_used_bytes), 0) FROM users WHERE tenant_id = $1`,
		tenantID).Scan(&used)
	return used, err
}

// AddCreditTx inserts a billing credit within an existing transaction.
func (s *BillingStore) AddCreditTx(ctx context.Context, tx pgx.Tx, credit *BillingCredit) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO billing_credits (credit_id, tenant_id, tier, mailbox_quota, valid_from, valid_until, token_hash, price_cents_each)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		credit.CreditID, credit.TenantID, credit.Tier, credit.MailboxQuota,
		credit.ValidFrom, credit.ValidUntil, credit.TokenHash, credit.PriceCentsEach,
	)
	if err != nil {
		return fmt.Errorf("add billing credit: %w", err)
	}
	return nil
}

// BeginTx starts a new database transaction.
func (s *BillingStore) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.DB.Pool.Begin(ctx)
}
