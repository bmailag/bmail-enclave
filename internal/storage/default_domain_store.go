package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// DefaultDomain represents a row in the default_domains table.
type DefaultDomain struct {
	Domain       string `db:"domain"`
	DisplayOrder int    `db:"display_order"`
	Enabled      bool   `db:"enabled"`
}

// DefaultDomainStore provides default-domain DB operations.
type DefaultDomainStore struct {
	DB *DB
}

// NewDefaultDomainStore returns a new DefaultDomainStore.
func NewDefaultDomainStore(db *DB) *DefaultDomainStore {
	return &DefaultDomainStore{DB: db}
}

// ListEnabled returns all enabled default domains ordered by display_order.
func (s *DefaultDomainStore) ListEnabled(ctx context.Context) ([]DefaultDomain, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT domain, display_order, enabled FROM default_domains
		 WHERE enabled = true ORDER BY display_order, domain`)
	if err != nil {
		return nil, fmt.Errorf("list enabled default domains: %w", err)
	}
	defer rows.Close()

	var domains []DefaultDomain
	for rows.Next() {
		var d DefaultDomain
		if err := rows.Scan(&d.Domain, &d.DisplayOrder, &d.Enabled); err != nil {
			return nil, fmt.Errorf("scan default domain: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

// ListAll returns all default domains (including disabled), ordered by display_order.
func (s *DefaultDomainStore) ListAll(ctx context.Context) ([]DefaultDomain, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT domain, display_order, enabled FROM default_domains
		 ORDER BY display_order, domain`)
	if err != nil {
		return nil, fmt.Errorf("list all default domains: %w", err)
	}
	defer rows.Close()

	var domains []DefaultDomain
	for rows.Next() {
		var d DefaultDomain
		if err := rows.Scan(&d.Domain, &d.DisplayOrder, &d.Enabled); err != nil {
			return nil, fmt.Errorf("scan default domain: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

// IsDefaultDomain checks if the given domain is an enabled default domain.
func (s *DefaultDomainStore) IsDefaultDomain(ctx context.Context, domain string) (bool, error) {
	var exists bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM default_domains WHERE domain = $1 AND enabled = true)`,
		domain,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check default domain: %w", err)
	}
	return exists, nil
}

// Add adds a new default domain.
func (s *DefaultDomainStore) Add(ctx context.Context, domain string, displayOrder int) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO default_domains (domain, display_order, enabled) VALUES ($1, $2, true)`,
		domain, displayOrder,
	)
	if err != nil {
		return fmt.Errorf("add default domain: %w", err)
	}
	return nil
}

// Remove deletes a default domain.
func (s *DefaultDomainStore) Remove(ctx context.Context, domain string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM default_domains WHERE domain = $1`, domain,
	)
	if err != nil {
		return fmt.Errorf("remove default domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("default domain not found: %s", domain)
	}
	return nil
}

// SetEnabled enables or disables a default domain.
func (s *DefaultDomainStore) SetEnabled(ctx context.Context, domain string, enabled bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE default_domains SET enabled = $2 WHERE domain = $1`,
		domain, enabled,
	)
	if err != nil {
		return fmt.Errorf("set default domain enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("default domain not found: %s", domain)
	}
	return nil
}

// UpdateOrder updates the display_order of a default domain.
func (s *DefaultDomainStore) UpdateOrder(ctx context.Context, domain string, order int) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE default_domains SET display_order = $2 WHERE domain = $1`,
		domain, order,
	)
	if err != nil {
		return fmt.Errorf("update default domain order: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("default domain not found: %s", domain)
	}
	return nil
}

// Get retrieves a single default domain by name.
func (s *DefaultDomainStore) Get(ctx context.Context, domain string) (*DefaultDomain, error) {
	d := &DefaultDomain{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT domain, display_order, enabled FROM default_domains WHERE domain = $1`,
		domain,
	).Scan(&d.Domain, &d.DisplayOrder, &d.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("default domain not found: %s", domain)
	}
	if err != nil {
		return nil, fmt.Errorf("get default domain: %w", err)
	}
	return d, nil
}
