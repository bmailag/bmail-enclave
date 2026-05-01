package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AutocryptKey represents a cached Autocrypt key learned from inbound messages.
type AutocryptKey struct {
	Email         string    `db:"email"`
	TenantID      uuid.UUID `db:"tenant_id"`
	PGPKey        string    `db:"pgp_key"`
	LastSeen      time.Time `db:"last_seen"`
	PreferEncrypt string    `db:"prefer_encrypt"`
}

// AutocryptStore provides operations on the autocrypt_keys table.
type AutocryptStore struct {
	DB *DB
}

// NewAutocryptStore returns a new AutocryptStore.
func NewAutocryptStore(db *DB) *AutocryptStore {
	return &AutocryptStore{DB: db}
}

// UpsertAutocryptKey inserts or updates an Autocrypt key for the given email.
func (s *AutocryptStore) UpsertAutocryptKey(ctx context.Context, email string, tenantID uuid.UUID, pgpKey, preferEncrypt string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO autocrypt_keys (email, tenant_id, pgp_key, last_seen, prefer_encrypt)
		 VALUES ($1, $2, $3, NOW(), $4)
		 ON CONFLICT (tenant_id, email) DO UPDATE SET
		   pgp_key = EXCLUDED.pgp_key,
		   last_seen = NOW(),
		   prefer_encrypt = EXCLUDED.prefer_encrypt`,
		email, tenantID, pgpKey, preferEncrypt,
	)
	if err != nil {
		return fmt.Errorf("upsert autocrypt key: %w", err)
	}
	return nil
}

// GetAutocryptKey retrieves a cached Autocrypt key for an email address, scoped to a tenant.
func (s *AutocryptStore) GetAutocryptKey(ctx context.Context, email string, tenantID uuid.UUID) (*AutocryptKey, error) {
	k := &AutocryptKey{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT email, tenant_id, pgp_key, last_seen, prefer_encrypt
		 FROM autocrypt_keys WHERE email = $1 AND tenant_id = $2`, email, tenantID,
	).Scan(&k.Email, &k.TenantID, &k.PGPKey, &k.LastSeen, &k.PreferEncrypt)
	if err != nil {
		return nil, fmt.Errorf("get autocrypt key: %w", err)
	}
	return k, nil
}

// DeleteAutocryptKey removes a cached Autocrypt key, scoped to a tenant.
func (s *AutocryptStore) DeleteAutocryptKey(ctx context.Context, email string, tenantID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM autocrypt_keys WHERE email = $1 AND tenant_id = $2`, email, tenantID,
	)
	return err
}

// CleanupStaleKeys removes Autocrypt keys not seen in the given duration.
func (s *AutocryptStore) CleanupStaleKeys(ctx context.Context, maxAge time.Duration) (int64, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM autocrypt_keys WHERE last_seen < $1`,
		time.Now().Add(-maxAge),
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup stale autocrypt keys: %w", err)
	}
	return tag.RowsAffected(), nil
}
