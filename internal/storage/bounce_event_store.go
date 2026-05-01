package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BounceEvent is one row of the bounce_events table — a permanent
// remote-side rejection of a message the user sent. Populated by
// smtp-outbound when a 5xx hits during DATA delivery; surfaced to
// support staff so they can see *why* a user was flagged, not just
// the count.
type BounceEvent struct {
	BounceID    uuid.UUID `json:"bounce_id"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Recipient   string    `json:"recipient"`
	SMTPCode    string    `json:"smtp_code,omitempty"`
	SMTPMessage string    `json:"smtp_message,omitempty"`
	BounceType  string    `json:"bounce_type"` // 'permanent' | 'transient'
	OccurredAt  time.Time `json:"occurred_at"`
}

// BounceEventStore wraps inserts and reads on the bounce_events table.
// Two writers (smtp-outbound on each bounce) and one reader (support
// panel /admin/users/{id}/bounces) share this store.
type BounceEventStore struct {
	DB *DB
}

func NewBounceEventStore(db *DB) *BounceEventStore { return &BounceEventStore{DB: db} }

// Insert records a bounce event. bounceType must be 'permanent' or
// 'transient' (CHECK constraint enforces it). Best-effort — callers
// log on error but should not block the SMTP path on persistence.
func (s *BounceEventStore) Insert(ctx context.Context, ev *BounceEvent) error {
	if ev.BounceType == "" {
		ev.BounceType = "permanent"
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO bounce_events (user_id, tenant_id, recipient, smtp_code, smtp_message, bounce_type)
		 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6)`,
		ev.UserID, ev.TenantID, ev.Recipient, ev.SMTPCode, ev.SMTPMessage, ev.BounceType,
	)
	if err != nil {
		return fmt.Errorf("insert bounce_event: %w", err)
	}
	return nil
}

// ListByUser returns the most recent bounce events for the given user.
// limit is clamped to [1, 200]; default 50.
func (s *BounceEventStore) ListByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*BounceEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT bounce_id, user_id, tenant_id, recipient,
		        COALESCE(smtp_code, ''), COALESCE(smtp_message, ''),
		        bounce_type, occurred_at
		 FROM bounce_events
		 WHERE user_id = $1
		 ORDER BY occurred_at DESC
		 LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list bounce_events: %w", err)
	}
	defer rows.Close()
	out := []*BounceEvent{}
	for rows.Next() {
		ev := &BounceEvent{}
		if err := rows.Scan(&ev.BounceID, &ev.UserID, &ev.TenantID, &ev.Recipient,
			&ev.SMTPCode, &ev.SMTPMessage, &ev.BounceType, &ev.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan bounce_event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
