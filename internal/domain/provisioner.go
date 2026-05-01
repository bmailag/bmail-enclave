package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bmailag/bmail/internal/storage"
	"github.com/bmailag/bmail/internal/tee"
)

// Provisioner handles tenant creation with DKIM key provisioning.
// It wraps the domain store and TEE runtime to ensure every tenant
// gets properly initialized DKIM keys (sealed via SGX enclave).
type Provisioner struct {
	domainStore *storage.DomainStore
	teeRuntime  tee.TEERuntime
	dkimClient  *DKIMClient // If set, delegates DKIM key generation to the smtp-outbound enclave.
}

// NewProvisioner creates a new domain provisioner.
func NewProvisioner(domainStore *storage.DomainStore, teeRuntime tee.TEERuntime) *Provisioner {
	return &Provisioner{
		domainStore: domainStore,
		teeRuntime:  teeRuntime,
	}
}

// SetDKIMClient sets the DKIM client for delegating key generation to the smtp-outbound enclave.
func (p *Provisioner) SetDKIMClient(c *DKIMClient) {
	p.dkimClient = c
}

// EnsureTenantWithDKIM gets or creates a tenant with fully provisioned DKIM keys.
// Unlike the bare EnsureTenant in auth_store.go, this generates and seals DKIM
// keys when creating a new tenant, so outbound mail is properly signed.
func (p *Provisioner) EnsureTenantWithDKIM(ctx context.Context, domain string) (uuid.UUID, error) {
	// Check if tenant already exists.
	existing, err := p.domainStore.GetTenantByDomain(ctx, domain)
	if err == nil && existing != nil {
		// If tenant exists but has no DKIM keys, provision them now.
		if existing.DKIMPublicKey == "" {
			if provErr := p.provisionDKIM(ctx, existing.TenantID, domain); provErr != nil {
				// Non-fatal: tenant exists, DKIM can be set up later.
				return existing.TenantID, nil
			}
		}
		return existing.TenantID, nil
	}

	// Create new tenant with DKIM keys.
	sealedKey, pubKeyB64, selector, err := p.generateDKIM(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	tenant := &storage.Tenant{
		TenantID:                uuid.New(),
		Domain:                  domain,
		DKIMPrivateKeyEncrypted: sealedKey,
		DKIMPublicKey:           pubKeyB64,
		DKIMSelector:            selector,
		Tier:                    "mail",
		Verified:                false,
	}

	if err := p.domainStore.CreateTenant(ctx, tenant); err != nil {
		// Race condition: another instance created it. Fetch and return.
		existing, fetchErr := p.domainStore.GetTenantByDomain(ctx, domain)
		if fetchErr != nil {
			return uuid.Nil, fmt.Errorf("create tenant race: %w", err)
		}
		return existing.TenantID, nil
	}

	return tenant.TenantID, nil
}

// provisionDKIM generates and stores DKIM keys for an existing tenant.
func (p *Provisioner) provisionDKIM(ctx context.Context, tenantID uuid.UUID, domain string) error {
	sealedKey, pubKeyB64, selector, err := p.generateDKIM(ctx)
	if err != nil {
		return err
	}
	return p.domainStore.UpdateTenantDKIM(ctx, tenantID, sealedKey, pubKeyB64, selector)
}

// generateDKIM generates a DKIM key pair, delegating to the smtp-outbound enclave when available.
func (p *Provisioner) generateDKIM(ctx context.Context) (sealedKey []byte, pubKey, selector string, err error) {
	if p.dkimClient != nil {
		resp, err := p.dkimClient.GenerateDKIM(ctx)
		if err != nil {
			return nil, "", "", fmt.Errorf("generate DKIM key via enclave: %w", err)
		}
		return resp.Ed25519.SealedPrivateKey, resp.Ed25519.PublicKey, resp.Ed25519.Selector, nil
	}
	privKey, pubKeyB64, err := GenerateDKIMKeyPair()
	if err != nil {
		return nil, "", "", fmt.Errorf("generate DKIM key: %w", err)
	}
	sel := fmt.Sprintf("%s-%d", DefaultDKIMSelector, time.Now().Unix())
	sealed, err := p.teeRuntime.Seal([]byte(privKey))
	if err != nil {
		return nil, "", "", fmt.Errorf("seal DKIM key: %w", err)
	}
	return sealed, pubKeyB64, sel, nil
}
