package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LabelStore wraps DB and provides label-related database operations.
type LabelStore struct {
	DB *DB
}

// NewLabelStore returns a new LabelStore backed by the given DB.
func NewLabelStore(db *DB) *LabelStore {
	return &LabelStore{DB: db}
}

// CreateLabel inserts a new label.
func (s *LabelStore) CreateLabel(ctx context.Context, label *Label) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO labels (label_id, user_id, tenant_id, name_encrypted, color, sort_order)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		label.LabelID, label.UserID, label.TenantID, label.NameEncrypted, label.Color, label.SortOrder,
	)
	if err != nil {
		return fmt.Errorf("create label: %w", err)
	}
	return nil
}

// ListLabels returns all labels for a user within a tenant.
func (s *LabelStore) ListLabels(ctx context.Context, userID, tenantID uuid.UUID) ([]*Label, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT label_id, user_id, tenant_id, name_encrypted, color, sort_order, created_at
		 FROM labels WHERE user_id = $1 AND tenant_id = $2 ORDER BY sort_order ASC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list labels: %w", err)
	}
	defer rows.Close()

	var labels []*Label
	for rows.Next() {
		l := &Label{}
		if err := rows.Scan(&l.LabelID, &l.UserID, &l.TenantID, &l.NameEncrypted, &l.Color, &l.SortOrder, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan label: %w", err)
		}
		labels = append(labels, l)
	}
	return labels, rows.Err()
}

// GetLabel retrieves a label by ID for the given user and tenant.
func (s *LabelStore) GetLabel(ctx context.Context, labelID, userID, tenantID uuid.UUID) (*Label, error) {
	l := &Label{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT label_id, user_id, tenant_id, name_encrypted, color, sort_order, created_at
		 FROM labels WHERE label_id = $1 AND user_id = $2 AND tenant_id = $3`,
		labelID, userID, tenantID,
	).Scan(&l.LabelID, &l.UserID, &l.TenantID, &l.NameEncrypted, &l.Color, &l.SortOrder, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("label not found: %s", labelID)
	}
	if err != nil {
		return nil, fmt.Errorf("get label: %w", err)
	}
	return l, nil
}

// UpdateLabel updates a label's name and color.
func (s *LabelStore) UpdateLabel(ctx context.Context, labelID, userID, tenantID uuid.UUID, nameEncrypted []byte, color string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE labels SET name_encrypted = $4, color = $5
		 WHERE label_id = $1 AND user_id = $2 AND tenant_id = $3`,
		labelID, userID, tenantID, nameEncrypted, color,
	)
	if err != nil {
		return fmt.Errorf("update label: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("label not found: %s", labelID)
	}
	return nil
}

// DeleteLabel removes a label.
func (s *LabelStore) DeleteLabel(ctx context.Context, labelID, userID, tenantID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM labels WHERE label_id = $1 AND user_id = $2 AND tenant_id = $3`,
		labelID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete label: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("label not found: %s", labelID)
	}
	return nil
}

// AddLabelsToMessages adds labels to messages, verifying ownership via user_id and tenant_id.
func (s *LabelStore) AddLabelsToMessages(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID, labelIDs []uuid.UUID) error {
	for _, msgID := range messageIDs {
		for _, lblID := range labelIDs {
			// Only insert if both the message and label belong to this user/tenant.
			_, err := s.DB.Pool.Exec(ctx,
				`INSERT INTO message_labels (message_id, label_id)
				 SELECT $1, $2
				 WHERE EXISTS (SELECT 1 FROM messages WHERE message_id = $1 AND user_id = $3 AND tenant_id = $4)
				   AND EXISTS (SELECT 1 FROM labels WHERE label_id = $2 AND user_id = $3 AND tenant_id = $4)
				 ON CONFLICT DO NOTHING`,
				msgID, lblID, userID, tenantID,
			)
			if err != nil {
				return fmt.Errorf("add label to message: %w", err)
			}
		}
	}
	return nil
}

// RemoveLabelsFromMessages removes labels from messages, verifying ownership.
func (s *LabelStore) RemoveLabelsFromMessages(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID, labelIDs []uuid.UUID) error {
	for _, msgID := range messageIDs {
		for _, lblID := range labelIDs {
			_, err := s.DB.Pool.Exec(ctx,
				`DELETE FROM message_labels
				 WHERE message_id = $1 AND label_id = $2
				   AND EXISTS (SELECT 1 FROM messages WHERE message_id = $1 AND user_id = $3 AND tenant_id = $4)`,
				msgID, lblID, userID, tenantID,
			)
			if err != nil {
				return fmt.Errorf("remove label from message: %w", err)
			}
		}
	}
	return nil
}

// GetLabelsForMessages returns label IDs for each message (batch).
func (s *LabelStore) GetLabelsForMessages(ctx context.Context, messageIDs []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT message_id, label_id FROM message_labels WHERE message_id = ANY($1)`,
		messageIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("get labels for messages: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID][]uuid.UUID)
	for rows.Next() {
		var msgID, lblID uuid.UUID
		if err := rows.Scan(&msgID, &lblID); err != nil {
			return nil, fmt.Errorf("scan message label: %w", err)
		}
		result[msgID] = append(result[msgID], lblID)
	}
	return result, rows.Err()
}
