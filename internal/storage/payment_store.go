package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PaymentStore wraps DB and provides spent-token database operations.
type PaymentStore struct {
	DB *DB
}

// NewPaymentStore returns a new PaymentStore backed by the given DB.
func NewPaymentStore(db *DB) *PaymentStore {
	return &PaymentStore{DB: db}
}

// InsertSpentToken atomically records a redeemed token hash to prevent double-spending.
// Returns ErrTokenAlreadySpent if the token was already redeemed.
func (s *PaymentStore) InsertSpentToken(ctx context.Context, tokenHash []byte, tier string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO spent_tokens (token_hash, tier, redeemed_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token_hash) DO NOTHING`,
		tokenHash, tier, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert spent token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTokenAlreadySpent
	}
	return nil
}

// ErrTokenAlreadySpent is returned when attempting to redeem a token that
// has already been spent.
var ErrTokenAlreadySpent = errors.New("token already spent")

// IsTokenSpent checks whether a token hash has already been redeemed.
func (s *PaymentStore) IsTokenSpent(ctx context.Context, tokenHash []byte) (bool, error) {
	var exists bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM spent_tokens WHERE token_hash = $1)`,
		tokenHash,
	).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check spent token: %w", err)
	}
	return exists, nil
}

// ErrFakeIDAlreadyMinted is returned when a subscription attempts to mint a
// second Fake ID credential. Enforces the one-Fake-ID-per-subscription rule
// inside the payment enclave.
var ErrFakeIDAlreadyMinted = errors.New("fakeid already minted for this subscription")

// MarkFakeIDMinted is the enclave's secondary anti-duplicate guard. Since
// the authoritative 1-per-primary enforcement moved to the users table's
// has_fakeid column (migrations 087, 088; ClaimFakeIDSlot in AuthStore),
// this check is only here to prevent concurrent rapid-fire duplicates from
// racing past the primary-side gate — for example, two concurrent mint
// requests from the same subscription that both slip through the TOCTOU
// window. 30-second cooldown is well under the primary-side deadline so it
// never blocks a legitimate post-release re-mint.
func (s *PaymentStore) MarkFakeIDMinted(ctx context.Context, subscriptionID string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO fakeid_mint_flags (subscription_id, minted_at)
		 VALUES ($1, $2)
		 ON CONFLICT (subscription_id) DO UPDATE
		   SET minted_at = EXCLUDED.minted_at
		   WHERE fakeid_mint_flags.minted_at < now() - INTERVAL '30 seconds'`,
		subscriptionID, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("mark fakeid minted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrFakeIDAlreadyMinted
	}
	return nil
}

// HasFakeIDMinted reports whether a subscription has already minted a Fake ID.
// Read-only; use MarkFakeIDMinted for the atomic test-and-set.
func (s *PaymentStore) HasFakeIDMinted(ctx context.Context, subscriptionID string) (bool, error) {
	var exists bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM fakeid_mint_flags WHERE subscription_id = $1)`,
		subscriptionID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check fakeid minted: %w", err)
	}
	return exists, nil
}
