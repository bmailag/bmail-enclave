package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AutoReplyStore wraps DB and provides auto-reply settings operations.
type AutoReplyStore struct {
	DB *DB
}

// NewAutoReplyStore returns a new AutoReplyStore.
func NewAutoReplyStore(db *DB) *AutoReplyStore {
	return &AutoReplyStore{DB: db}
}

// GetAutoReply retrieves auto-reply settings for a user.
func (s *AutoReplyStore) GetAutoReply(ctx context.Context, userID uuid.UUID) (*AutoReplySettings, error) {
	ar := &AutoReplySettings{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT user_id, tenant_id, enabled, subject, body, start_date, end_date, updated_at
		 FROM auto_reply_settings WHERE user_id = $1`,
		userID,
	).Scan(&ar.UserID, &ar.TenantID, &ar.Enabled, &ar.Subject, &ar.Body, &ar.StartDate, &ar.EndDate, &ar.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // no settings configured
	}
	if err != nil {
		return nil, fmt.Errorf("get auto reply: %w", err)
	}
	return ar, nil
}

// UpsertAutoReply creates or updates auto-reply settings.
func (s *AutoReplyStore) UpsertAutoReply(ctx context.Context, ar *AutoReplySettings) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO auto_reply_settings (user_id, tenant_id, enabled, subject, body, start_date, end_date, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		 ON CONFLICT (user_id) DO UPDATE SET
			tenant_id = $2, enabled = $3, subject = $4, body = $5, start_date = $6, end_date = $7, updated_at = now()`,
		ar.UserID, ar.TenantID, ar.Enabled, ar.Subject, ar.Body, ar.StartDate, ar.EndDate,
	)
	if err != nil {
		return fmt.Errorf("upsert auto reply: %w", err)
	}
	return nil
}
