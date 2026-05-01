package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuthEvent represents a security-relevant authentication event.
type AuthEvent struct {
	ID        uuid.UUID       `json:"id"`
	TenantID  uuid.UUID       `json:"tenant_id"`
	UserID    *uuid.UUID      `json:"user_id,omitempty"`
	EventType string          `json:"event_type"`
	IPHash    []byte          `json:"-"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// AuthEventStore provides auth event audit trail operations.
type AuthEventStore struct {
	DB *DB
}

// NewAuthEventStore returns a new AuthEventStore.
func NewAuthEventStore(db *DB) *AuthEventStore {
	return &AuthEventStore{DB: db}
}

// RecordEvent inserts a new auth event.
func (s *AuthEventStore) RecordEvent(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, eventType string, ipHash []byte, metadata json.RawMessage) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO auth_events (tenant_id, user_id, event_type, ip_hash, metadata)
		 VALUES ($1, $2, $3, $4, $5)`,
		tenantID, userID, eventType, ipHash, metadata,
	)
	if err != nil {
		return fmt.Errorf("record auth event: %w", err)
	}
	return nil
}

// ListEvents returns recent auth events for a user, ordered newest first.
func (s *AuthEventStore) ListEvents(ctx context.Context, userID uuid.UUID, limit, offset int) ([]AuthEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, tenant_id, user_id, event_type, ip_hash, metadata, created_at
		 FROM auth_events
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2 OFFSET $3`,
		userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list auth events: %w", err)
	}
	defer rows.Close()

	var events []AuthEvent
	for rows.Next() {
		var e AuthEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.UserID, &e.EventType, &e.IPHash, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan auth event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
