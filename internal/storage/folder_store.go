package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Default folder types.
const (
	FolderInbox   = "inbox"
	FolderSent    = "sent"
	FolderDrafts  = "drafts"
	FolderTrash   = "trash"
	FolderJunk    = "junk"
	FolderArchive = "archive"
	FolderSnoozed = "snoozed"
	FolderCustom  = "custom"
)

// defaultFolderTypes lists the standard folders created for every new user.
var defaultFolderTypes = []struct {
	Type      string
	SortOrder int
}{
	{FolderInbox, 0},
	{FolderSent, 1},
	{FolderDrafts, 2},
	{FolderTrash, 3},
	{FolderJunk, 4},
	{FolderArchive, 5},
}

// FolderStore wraps DB and provides folder-related database operations.
type FolderStore struct {
	DB *DB
}

// NewFolderStore returns a new FolderStore backed by the given DB.
func NewFolderStore(db *DB) *FolderStore {
	return &FolderStore{DB: db}
}

// CreateDefaultFolders creates the standard set of folders (inbox, sent, drafts, trash, junk) for a user.
func (s *FolderStore) CreateDefaultFolders(ctx context.Context, userID, tenantID uuid.UUID) error {
	for _, df := range defaultFolderTypes {
		_, err := s.DB.Pool.Exec(ctx,
			`INSERT INTO folders (folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), userID, tenantID, []byte(df.Type), df.Type, df.SortOrder,
		)
		if err != nil {
			return fmt.Errorf("create default folder %s: %w", df.Type, err)
		}
	}
	return nil
}

// CreateFolder inserts a new custom folder.
func (s *FolderStore) CreateFolder(ctx context.Context, folder *Folder) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO folders (folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order, parent_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		folder.FolderID, folder.UserID, folder.TenantID, folder.NameEncrypted, folder.FolderType, folder.SortOrder, folder.ParentID,
	)
	if err != nil {
		return fmt.Errorf("create folder: %w", err)
	}
	return nil
}

// ListFolders returns all folders for a user within a tenant, ordered by sort_order.
func (s *FolderStore) ListFolders(ctx context.Context, userID, tenantID uuid.UUID) ([]*Folder, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order, parent_id
		 FROM folders
		 WHERE user_id = $1 AND tenant_id = $2
		 ORDER BY sort_order ASC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	defer rows.Close()

	var folders []*Folder
	for rows.Next() {
		f := &Folder{}
		if err := rows.Scan(
			&f.FolderID, &f.UserID, &f.TenantID, &f.NameEncrypted, &f.FolderType, &f.SortOrder, &f.ParentID,
		); err != nil {
			return nil, fmt.Errorf("scan folder: %w", err)
		}
		folders = append(folders, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate folders: %w", err)
	}
	return folders, nil
}

// GetFolderByType returns the folder of the given type for a user within a tenant.
func (s *FolderStore) GetFolderByType(ctx context.Context, userID, tenantID uuid.UUID, folderType string) (*Folder, error) {
	f := &Folder{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order, parent_id
		 FROM folders
		 WHERE user_id = $1 AND tenant_id = $2 AND folder_type = $3`,
		userID, tenantID, folderType,
	).Scan(
		&f.FolderID, &f.UserID, &f.TenantID, &f.NameEncrypted, &f.FolderType, &f.SortOrder, &f.ParentID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("folder not found: type %s for user %s", folderType, userID)
	}
	if err != nil {
		return nil, fmt.Errorf("get folder by type: %w", err)
	}
	return f, nil
}

// GetFolderByID returns the folder with the given ID, scoped to the
// caller's user + tenant. Returns nil, nil when the folder doesn't
// exist or belongs to a different user (so callers can fall back to a
// default without distinguishing "missing" from "denied").
func (s *FolderStore) GetFolderByID(ctx context.Context, userID, tenantID, folderID uuid.UUID) (*Folder, error) {
	f := &Folder{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order, parent_id
		 FROM folders
		 WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID,
	).Scan(
		&f.FolderID, &f.UserID, &f.TenantID, &f.NameEncrypted, &f.FolderType, &f.SortOrder, &f.ParentID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get folder by id: %w", err)
	}
	return f, nil
}

// DeleteFolder removes a folder, but prevents deletion of default (non-custom) folders.
// Uses a transaction with FOR UPDATE to prevent TOCTOU race conditions.
func (s *FolderStore) DeleteFolder(ctx context.Context, folderID, userID, tenantID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete folder tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock the folder row and check type atomically.
	var folderType string
	err = tx.QueryRow(ctx,
		`SELECT folder_type FROM folders WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3 FOR UPDATE`,
		folderID, userID, tenantID,
	).Scan(&folderType)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("folder not found")
	}
	if err != nil {
		return fmt.Errorf("check folder type: %w", err)
	}
	if folderType != FolderCustom {
		return fmt.Errorf("cannot delete default folder")
	}

	// Move any messages in this folder to Trash before deleting,
	// otherwise the foreign key constraint on messages.folder_id blocks the delete.
	var trashID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT folder_id FROM folders WHERE user_id = $1 AND tenant_id = $2 AND folder_type = $3`,
		userID, tenantID, FolderTrash,
	).Scan(&trashID)
	if err != nil {
		return fmt.Errorf("find trash folder: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE messages SET folder_id = $1 WHERE folder_id = $2 AND user_id = $3 AND tenant_id = $4`,
		trashID, folderID, userID, tenantID,
	); err != nil {
		return fmt.Errorf("move messages to trash: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`DELETE FROM folders WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("folder not found: %s", folderID)
	}
	return tx.Commit(ctx)
}

// RenameFolder updates the encrypted name of a folder.
func (s *FolderStore) RenameFolder(ctx context.Context, folderID, userID, tenantID uuid.UUID, newNameEncrypted []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE folders SET name_encrypted = $4
		 WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID, newNameEncrypted,
	)
	if err != nil {
		return fmt.Errorf("rename folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("folder not found: %s", folderID)
	}
	return nil
}
