package storage

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// FakeIDSlotStore owns the two enclave-authoritative slot-state tables:
// fakeid_pending_slots and fakeid_consumed_slots (migration 089).
//
// All access is keyed by primary_tag = HMAC(fakeid_tag_key, primary_id).
// The tag is computed inside the payment enclave — this store never sees
// primary_id. That's what keeps bmail-side DB operators from linking slot
// rows to specific primaries; if the enclave's tag key stays sealed, these
// tables are opaque to everyone outside the enclave.
//
// Slot state is two-valued: either a primary has a row in
// fakeid_consumed_slots (they already have a Fake ID) or they don't
// (they can mint one). The earlier design also had fakeid_pending_slots
// — a short-TTL reservation taken at mint — but the pending state
// proved unnecessary: the consumed_slots primary-key is itself the
// 1-per-primary enforcement point, and skipping the pending write
// means abandoning a mint never locks the primary out. The pending
// table still exists (migration 089) but is no longer written or read;
// Phase 5 drops it.
type FakeIDSlotStore struct {
	DB *DB
}

// NewFakeIDSlotStore returns a slot store backed by the given DB.
func NewFakeIDSlotStore(db *DB) *FakeIDSlotStore {
	return &FakeIDSlotStore{DB: db}
}

// ErrSlotAlreadyTaken is returned from ClaimPending when the primary
// already has an unexpired pending row OR a consumed row. The enclave
// maps this to an HTTP 409 — the primary's UI should render "you already
// have a Fake ID" (consumed case) or "mint in progress, retry at T"
// (pending case). Callers distinguish via SlotStatus.
var ErrSlotAlreadyTaken = errors.New("fakeid slot already taken")

// SlotState is the two-valued result of StatusForTag.
type SlotState int

const (
	SlotFree SlotState = iota
	SlotConsumed
)

// SlotStatus is what the enclave returns to the primary backend on a
// status query.
type SlotStatus struct {
	State SlotState
}

// StatusForTag returns the current slot state for primaryTag.
func (s *FakeIDSlotStore) StatusForTag(ctx context.Context, primaryTag []byte) (SlotStatus, error) {
	var consumed bool
	if err := s.DB.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM fakeid_consumed_slots WHERE primary_tag = $1)`,
		primaryTag,
	).Scan(&consumed); err != nil {
		return SlotStatus{}, fmt.Errorf("check consumed: %w", err)
	}
	if consumed {
		return SlotStatus{State: SlotConsumed}, nil
	}
	return SlotStatus{State: SlotFree}, nil
}

// InsertConsumed inserts a consumed row and returns ErrSlotAlreadyTaken
// if one is already present. This is the 1-per-primary enforcement
// point — the enclave calls it inside verify-credential alongside the
// spent_tokens insert, and a conflict means someone else (the same
// primary from a different window) already registered first.
//
// Unlike SeedConsumed (which is idempotent for the Phase 4 backfill)
// this variant surfaces conflicts so the enclave can return 409 and
// the user's frontend can show "you already have a Fake ID".
func (s *FakeIDSlotStore) InsertConsumed(ctx context.Context, primaryTag []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO fakeid_consumed_slots (primary_tag, consumed_at)
		 VALUES ($1, now())
		 ON CONFLICT (primary_tag) DO NOTHING`,
		primaryTag,
	)
	if err != nil {
		return fmt.Errorf("insert consumed slot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSlotAlreadyTaken
	}
	return nil
}

// SeedConsumed inserts a consumed row unconditionally. Only the Phase 4
// backfill job calls this — the enclave's /admin/seed-consumed handler
// wraps it for each user.has_fakeid=TRUE row. Idempotent on primary-key
// conflict so the backfill is safe to re-run.
func (s *FakeIDSlotStore) SeedConsumed(ctx context.Context, primaryTag []byte, consumedAt time.Time) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO fakeid_consumed_slots (primary_tag, consumed_at)
		 VALUES ($1, $2)
		 ON CONFLICT (primary_tag) DO NOTHING`,
		primaryTag, consumedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("seed consumed slot: %w", err)
	}
	return nil
}
