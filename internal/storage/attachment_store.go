package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Attachment represents a row in the attachments table.
type Attachment struct {
	ID                   uuid.UUID  `db:"id"`
	MessageID            *uuid.UUID `db:"message_id"`
	UserID               uuid.UUID  `db:"user_id"`
	TenantID             uuid.UUID  `db:"tenant_id"`
	EncryptedFilename    []byte     `db:"encrypted_filename"`
	EncryptedContentType []byte     `db:"encrypted_content_type"`
	SizeBytes            int64      `db:"size_bytes"`
	BlobKey              string     `db:"blob_key"`
	CreatedAt            time.Time  `db:"created_at"`
	// E2E encrypted attachment key wrap fields (NULL for legacy unencrypted).
	KeyEphemeralPubkey     []byte `db:"key_ephemeral_pubkey"`
	EncryptedAttachmentKey []byte `db:"encrypted_attachment_key"`
}

// AttachmentStore wraps DB and provides attachment database operations.
type AttachmentStore struct {
	DB *DB
}

// NewAttachmentStore returns a new AttachmentStore.
func NewAttachmentStore(db *DB) *AttachmentStore {
	return &AttachmentStore{DB: db}
}

// CreateAttachment inserts a new attachment.
func (s *AttachmentStore) CreateAttachment(ctx context.Context, a *Attachment) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO attachments (id, message_id, user_id, tenant_id, encrypted_filename, encrypted_content_type, size_bytes, blob_key, created_at, key_ephemeral_pubkey, encrypted_attachment_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.ID, a.MessageID, a.UserID, a.TenantID, a.EncryptedFilename, a.EncryptedContentType, a.SizeBytes, a.BlobKey, a.CreatedAt, a.KeyEphemeralPubkey, a.EncryptedAttachmentKey,
	)
	if err != nil {
		return fmt.Errorf("create attachment: %w", err)
	}
	return nil
}

// GetAttachment retrieves an attachment by ID, scoped to a user and tenant.
func (s *AttachmentStore) GetAttachment(ctx context.Context, id, userID, tenantID uuid.UUID) (*Attachment, error) {
	a := &Attachment{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT id, message_id, user_id, tenant_id, encrypted_filename, encrypted_content_type, size_bytes, blob_key, created_at, key_ephemeral_pubkey, encrypted_attachment_key
		 FROM attachments WHERE id = $1 AND user_id = $2 AND tenant_id = $3`, id, userID, tenantID,
	).Scan(
		&a.ID, &a.MessageID, &a.UserID, &a.TenantID, &a.EncryptedFilename,
		&a.EncryptedContentType, &a.SizeBytes, &a.BlobKey, &a.CreatedAt,
		&a.KeyEphemeralPubkey, &a.EncryptedAttachmentKey,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("attachment not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get attachment: %w", err)
	}
	return a, nil
}

// ListAttachmentsByMessage returns all attachments for a message, scoped to a user and tenant.
func (s *AttachmentStore) ListAttachmentsByMessage(ctx context.Context, messageID, userID, tenantID uuid.UUID) ([]*Attachment, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, message_id, user_id, tenant_id, encrypted_filename, encrypted_content_type, size_bytes, blob_key, created_at, key_ephemeral_pubkey, encrypted_attachment_key
		 FROM attachments WHERE message_id = $1 AND user_id = $2 AND tenant_id = $3 ORDER BY created_at`, messageID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list attachments: %w", err)
	}
	defer rows.Close()

	var attachments []*Attachment
	for rows.Next() {
		a := &Attachment{}
		if err := rows.Scan(
			&a.ID, &a.MessageID, &a.UserID, &a.TenantID, &a.EncryptedFilename,
			&a.EncryptedContentType, &a.SizeBytes, &a.BlobKey, &a.CreatedAt,
			&a.KeyEphemeralPubkey, &a.EncryptedAttachmentKey,
		); err != nil {
			return nil, fmt.Errorf("scan attachment: %w", err)
		}
		attachments = append(attachments, a)
	}
	return attachments, rows.Err()
}

// DeleteAttachment removes an attachment, scoped to a user and tenant.
func (s *AttachmentStore) DeleteAttachment(ctx context.Context, id, userID, tenantID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM attachments WHERE id = $1 AND user_id = $2 AND tenant_id = $3`, id, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete attachment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("attachment not found")
	}
	return nil
}

// LinkAttachmentsToMessage sets the message_id on attachments atomically, scoped to a user and tenant.
func (s *AttachmentStore) LinkAttachmentsToMessage(ctx context.Context, userID, tenantID, messageID uuid.UUID, attachmentIDs []uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, aid := range attachmentIDs {
		_, err := tx.Exec(ctx,
			`UPDATE attachments SET message_id = $3 WHERE id = $1 AND user_id = $2 AND tenant_id = $4`,
			aid, userID, messageID, tenantID,
		)
		if err != nil {
			return fmt.Errorf("link attachment %s: %w", aid, err)
		}
	}
	return tx.Commit(ctx)
}
