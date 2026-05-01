package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AutoReplyDedupStore tracks the most recent auto-reply sent from a
// given user to a given (blind-indexed) sender, so we don't blast
// auto-replies on every inbound message from the same correspondent.
//
// Phase B2 replaces the worker's Redis NX dedup with this table because
// the smtp-inbound enclave triggers auto-replies directly inside SGX
// and can't reach Redis. The table never stores cleartext sender
// addresses — only HMAC blind indexes scoped per user.
type AutoReplyDedupStore struct {
	DB *DB
}

// NewAutoReplyDedupStore returns a new AutoReplyDedupStore.
func NewAutoReplyDedupStore(db *DB) *AutoReplyDedupStore {
	return &AutoReplyDedupStore{DB: db}
}

// TryRecordAutoReply attempts to record that an auto-reply was just
// sent from `userID` to the sender identified by `senderBlindIndex`.
// Returns true on the first call within the TTL window, false if a
// previous record is still fresh (within ttl). The caller should only
// dispatch the auto-reply when this returns true.
//
// Implementation: INSERT ... ON CONFLICT DO UPDATE WHERE the existing
// row's last_sent_at is older than (now - ttl). If the WHERE matches,
// the row is updated and the insert "wins"; otherwise the row is
// untouched and the insert is treated as a duplicate.
func (s *AutoReplyDedupStore) TryRecordAutoReply(ctx context.Context, userID, tenantID uuid.UUID, senderBlindIndex string, ttl time.Duration) (bool, error) {
	if senderBlindIndex == "" {
		return false, fmt.Errorf("auto reply dedup: empty sender blind index")
	}
	cutoff := time.Now().Add(-ttl)
	tag, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO auto_reply_dedup (user_id, tenant_id, sender_blind_index, last_sent_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (user_id, sender_blind_index) DO UPDATE
		 SET last_sent_at = now(), tenant_id = EXCLUDED.tenant_id
		 WHERE auto_reply_dedup.last_sent_at < $4`,
		userID, tenantID, senderBlindIndex, cutoff,
	)
	if err != nil {
		return false, fmt.Errorf("auto reply dedup upsert: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// SweepStale deletes dedup rows older than `older`. Intended to be
// called periodically by the worker (or any background sweeper). Not
// safety-critical — stale rows just waste a few bytes.
func (s *AutoReplyDedupStore) SweepStale(ctx context.Context, older time.Duration) (int64, error) {
	cutoff := time.Now().Add(-older)
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM auto_reply_dedup WHERE last_sent_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("auto reply dedup sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}
