package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DriveFolder represents a row in the drive_folders table.
// Post-migration-077, the folder row itself carries NO encrypted
// material — all crypto state (name, keys) lives in the epoch
// tables (drive_folder_epoch_keys + drive_folder_epoch_names).
type DriveFolder struct {
	FolderID     uuid.UUID  `db:"folder_id"`
	UserID       uuid.UUID  `db:"user_id"`
	TenantID     uuid.UUID  `db:"tenant_id"`
	ParentID     *uuid.UUID `db:"parent_id"`
	CurrentEpoch int        `db:"current_epoch"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
}

// DriveFolderEpochKey is one row in drive_folder_epoch_keys: the FCK
// for a given epoch wrapped under a specific recipient's X25519 pubkey.
type DriveFolderEpochKey struct {
	FolderID           uuid.UUID `db:"folder_id"`
	Epoch              int       `db:"epoch"`
	RecipientUserID    uuid.UUID `db:"recipient_user_id"`
	TenantID           uuid.UUID `db:"tenant_id"`
	WrappedFCK         []byte    `db:"wrapped_fck"`
	WrappedFCKEphPubkey []byte   `db:"wrapped_fck_eph_pubkey"`
	CreatedAt          time.Time `db:"created_at"`
}

// DriveFolderEpochName is the folder's name encrypted under an epoch's FCK.
type DriveFolderEpochName struct {
	FolderID      uuid.UUID `db:"folder_id"`
	Epoch         int       `db:"epoch"`
	EncryptedName []byte    `db:"encrypted_name"`
}

// DriveFolderShareMember is a membership row in drive_folder_shares.
type DriveFolderShareMember struct {
	FolderID         uuid.UUID  `db:"folder_id"`
	RecipientUserID  uuid.UUID  `db:"recipient_user_id"`
	TenantID         uuid.UUID  `db:"tenant_id"`
	OwnerUserID      uuid.UUID  `db:"owner_user_id"`
	JoinedEpoch      int        `db:"joined_epoch"`
	PastEpochAccess  bool       `db:"past_epoch_access"`
	CanEdit          bool       `db:"can_edit"`
	ExpiresAt        *time.Time `db:"expires_at"`
	CreatedAt        time.Time  `db:"created_at"`
}

// DriveFile represents a row in the drive_files table.
type DriveFile struct {
	FileID               uuid.UUID  `db:"file_id"`
	UserID               uuid.UUID  `db:"user_id"`
	TenantID             uuid.UUID  `db:"tenant_id"`
	FolderID             *uuid.UUID `db:"folder_id"`
	EncryptedName        []byte     `db:"encrypted_name"`
	EncryptedContentType []byte     `db:"encrypted_content_type"`
	SizeBytes            int64      `db:"size_bytes"` // encrypted blob size on disk
	OriginalSizeBytes    *int64     `db:"original_size_bytes"` // plaintext file size; NULL for legacy rows
	BlobRef              string     `db:"blob_ref"`
	EphemeralPubkey      []byte     `db:"ephemeral_pubkey"`
	EncryptedFileKey     []byte     `db:"encrypted_file_key"`
	// FCKWrappedMessageKey is the file's per-file message_key wrapped
	// under FCK_{Epoch} using XChaCha20-Poly1305 with file_id as AAD.
	// Format: nonce(24) || ciphertext || tag(16). NULL for files in
	// non-shared folders. Recipients unwrap with the FCK they obtained
	// from drive_folder_epoch_keys for this file's epoch.
	FCKWrappedMessageKey []byte     `db:"fck_wrapped_message_key"`
	Epoch                int        `db:"epoch"`
	// EncryptionFormat identifies which AEAD was used for the body blob.
	// "xchacha" = XChaCha20-Poly1305 (legacy WASM path).
	// "aesgcm"  = AES-256-GCM (Web Crypto path, single blob).
	// "aesgcm-chunked" = AES-256-GCM chunked (64MB per chunk, stored separately).
	EncryptionFormat     string     `db:"encryption_format"`
	// ChunkCount is 0 for single-blob files. >0 = number of separately stored
	// encrypted chunks. Each chunk is at BlobRef + "/N" (0-indexed).
	ChunkCount           int        `db:"chunk_count"`
	Starred              bool       `db:"starred"`
	Trashed              bool       `db:"trashed"`
	TrashedAt            *time.Time `db:"trashed_at"`
	CreatedAt            time.Time  `db:"created_at"`
	UpdatedAt            time.Time  `db:"updated_at"`
}

// DriveStore wraps DB and provides drive-related database operations.
type DriveStore struct {
	DB *DB
}

// NewDriveStore returns a new DriveStore backed by the given DB.
func NewDriveStore(db *DB) *DriveStore {
	return &DriveStore{DB: db}
}

// --- Folder columns and scanner ---

const driveFolderColumns = `folder_id, user_id, tenant_id, parent_id,
	current_epoch, created_at, updated_at`

func scanDriveFolder(rows pgx.Rows) (*DriveFolder, error) {
	f := &DriveFolder{}
	if err := rows.Scan(
		&f.FolderID, &f.UserID, &f.TenantID, &f.ParentID,
		&f.CurrentEpoch, &f.CreatedAt, &f.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return f, nil
}

// --- File columns and scanner ---

const driveFileColumns = `file_id, user_id, tenant_id, folder_id,
	encrypted_name, encrypted_content_type, size_bytes, original_size_bytes, blob_ref,
	ephemeral_pubkey, encrypted_file_key, fck_wrapped_message_key, epoch, encryption_format,
	chunk_count,
	starred, trashed, trashed_at,
	created_at, updated_at`

func scanDriveFile(rows pgx.Rows) (*DriveFile, error) {
	f := &DriveFile{}
	if err := rows.Scan(
		&f.FileID, &f.UserID, &f.TenantID, &f.FolderID,
		&f.EncryptedName, &f.EncryptedContentType, &f.SizeBytes, &f.OriginalSizeBytes, &f.BlobRef,
		&f.EphemeralPubkey, &f.EncryptedFileKey, &f.FCKWrappedMessageKey, &f.Epoch, &f.EncryptionFormat,
		&f.ChunkCount,
		&f.Starred, &f.Trashed, &f.TrashedAt,
		&f.CreatedAt, &f.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return f, nil
}

// --- Folder CRUD ---

// CreateFolderInput holds the data needed to create a folder in the
// epoch model. The caller generates FCK_0 client-side, wraps it for
// the owner, and encrypts the folder name under FCK_0.
type CreateFolderInput struct {
	Folder          *DriveFolder
	WrappedFCK      []byte // FCK_0 wrapped for owner
	WrappedFCKEph   []byte // ephemeral pubkey from the wrap
	EncryptedName   []byte // folder name encrypted under FCK_0
}

// CreateFolder inserts a new drive folder + its epoch 0 key wrap +
// epoch 0 encrypted name in one transaction.
func (s *DriveStore) CreateFolder(ctx context.Context, in CreateFolderInput) error {
	f := in.Folder
	if f.FolderID == uuid.Nil {
		f.FolderID = uuid.New()
	}
	now := time.Now()
	f.CreatedAt = now
	f.UpdatedAt = now
	f.CurrentEpoch = 0

	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin create folder tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folders (folder_id, user_id, tenant_id, parent_id,
			current_epoch, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		f.FolderID, f.UserID, f.TenantID, f.ParentID,
		f.CurrentEpoch, f.CreatedAt, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert folder: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folder_epoch_keys
			(folder_id, epoch, recipient_user_id, tenant_id, wrapped_fck, wrapped_fck_eph_pubkey)
		 VALUES ($1, 0, $2, $3, $4, $5)`,
		f.FolderID, f.UserID, f.TenantID, in.WrappedFCK, in.WrappedFCKEph,
	)
	if err != nil {
		return fmt.Errorf("insert epoch 0 key: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folder_epoch_names (folder_id, epoch, encrypted_name)
		 VALUES ($1, 0, $2)`,
		f.FolderID, in.EncryptedName,
	)
	if err != nil {
		return fmt.Errorf("insert epoch 0 name: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit create folder tx: %w", err)
	}
	return nil
}

// GetFolder retrieves a single drive folder by ID, scoped to user+tenant.
func (s *DriveStore) GetFolder(ctx context.Context, userID, tenantID, folderID uuid.UUID) (*DriveFolder, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFolderColumns+`
		 FROM drive_folders
		 WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get drive folder: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("drive folder not found")
	}
	return scanDriveFolder(rows)
}

// ListFolders returns all folders for a user, optionally filtered by parent_id.
func (s *DriveStore) ListFolders(ctx context.Context, userID, tenantID uuid.UUID, parentID *uuid.UUID) ([]*DriveFolder, error) {
	var rows pgx.Rows
	var err error
	if parentID != nil {
		rows, err = s.DB.Pool.Query(ctx,
			`SELECT `+driveFolderColumns+`
			 FROM drive_folders
			 WHERE user_id = $1 AND tenant_id = $2 AND parent_id = $3
			 ORDER BY created_at`,
			userID, tenantID, *parentID,
		)
	} else {
		rows, err = s.DB.Pool.Query(ctx,
			`SELECT `+driveFolderColumns+`
			 FROM drive_folders
			 WHERE user_id = $1 AND tenant_id = $2 AND parent_id IS NULL
			 ORDER BY created_at`,
			userID, tenantID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list drive folders: %w", err)
	}
	defer rows.Close()

	var folders []*DriveFolder
	for rows.Next() {
		f, err := scanDriveFolder(rows)
		if err != nil {
			return nil, fmt.Errorf("scan drive folder: %w", err)
		}
		folders = append(folders, f)
	}
	return folders, nil
}

// UpdateFolder modifies an existing drive folder (parent_id move only —
// name changes go through UpdateFolderName which writes to the epoch
// name table).
func (s *DriveStore) UpdateFolder(ctx context.Context, f *DriveFolder) error {
	f.UpdatedAt = time.Now()
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_folders SET parent_id = $4, updated_at = $5
		 WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		f.FolderID, f.UserID, f.TenantID,
		f.ParentID, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update drive folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive folder not found")
	}
	return nil
}

// UpdateFolderName updates the encrypted name for a folder at its
// current epoch. The caller encrypts the new name under the current
// epoch's FCK and posts it here.
func (s *DriveStore) UpdateFolderName(ctx context.Context, folderID uuid.UUID, encryptedName []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_folder_epoch_names SET encrypted_name = $1
		 WHERE folder_id = $2 AND epoch = (
		   SELECT current_epoch FROM drive_folders WHERE folder_id = $2
		 )`,
		encryptedName, folderID,
	)
	if err != nil {
		return fmt.Errorf("update folder name: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("folder epoch name not found")
	}
	return nil
}

// DeleteFolder removes a drive folder by ID. Subfolders cascade-delete via
// the FK constraint; files inside the deleted folders fall back to root
// (folder_id SET NULL). Use DeleteFolderCascadeTrash if you want to also
// move all contained files to Trash atomically.
func (s *DriveStore) DeleteFolder(ctx context.Context, userID, tenantID, folderID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM drive_folders WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete drive folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive folder not found")
	}
	return nil
}

// DeleteFolderCascadeTrash trashes every file in the folder and its descendant
// subfolders, then deletes the folder. Uses a single transaction with a
// recursive CTE so the operation is atomic. Returns the number of files
// that were moved to Trash.
func (s *DriveStore) DeleteFolderCascadeTrash(ctx context.Context, userID, tenantID, folderID uuid.UUID) (int64, error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Trash all files in the target folder and any descendant subfolder.
	tag, err := tx.Exec(ctx,
		`WITH RECURSIVE subfolders AS (
			SELECT folder_id FROM drive_folders
			WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3
			UNION ALL
			SELECT df.folder_id FROM drive_folders df
			JOIN subfolders sf ON df.parent_id = sf.folder_id
			WHERE df.user_id = $2 AND df.tenant_id = $3
		)
		UPDATE drive_files
		SET trashed = true, trashed_at = now(), updated_at = now()
		WHERE user_id = $2 AND tenant_id = $3
		  AND folder_id IN (SELECT folder_id FROM subfolders)
		  AND NOT trashed`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return 0, fmt.Errorf("cascade trash files: %w", err)
	}
	trashed := tag.RowsAffected()

	// Now delete the folder (subfolders cascade via FK).
	tag, err = tx.Exec(ctx,
		`DELETE FROM drive_folders WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return 0, fmt.Errorf("delete drive folder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, fmt.Errorf("drive folder not found")
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return trashed, nil
}

// --- File CRUD ---

// CreateFile inserts a new drive file.
func (s *DriveStore) CreateFile(ctx context.Context, f *DriveFile) error {
	if f.FileID == uuid.Nil {
		f.FileID = uuid.New()
	}
	now := time.Now()
	f.CreatedAt = now
	f.UpdatedAt = now
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO drive_files (file_id, user_id, tenant_id, folder_id,
			encrypted_name, encrypted_content_type, size_bytes, original_size_bytes, blob_ref,
			ephemeral_pubkey, encrypted_file_key, fck_wrapped_message_key, epoch, encryption_format,
			chunk_count,
			starred, trashed, trashed_at,
			created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		f.FileID, f.UserID, f.TenantID, f.FolderID,
		f.EncryptedName, f.EncryptedContentType, f.SizeBytes, f.OriginalSizeBytes, f.BlobRef,
		f.EphemeralPubkey, f.EncryptedFileKey, f.FCKWrappedMessageKey, f.Epoch, f.EncryptionFormat,
		f.ChunkCount,
		f.Starred, f.Trashed, f.TrashedAt,
		f.CreatedAt, f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create drive file: %w", err)
	}
	return nil
}

// GetFile retrieves a single drive file by ID, scoped to user+tenant.
func (s *DriveStore) GetFile(ctx context.Context, userID, tenantID, fileID uuid.UUID) (*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFileColumns+`
		 FROM drive_files
		 WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3`,
		fileID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get drive file: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("drive file not found")
	}
	return scanDriveFile(rows)
}

// ListFiles returns all non-trashed files for a user, optionally filtered by folder_id.
func (s *DriveStore) ListFiles(ctx context.Context, userID, tenantID uuid.UUID, folderID *uuid.UUID) ([]*DriveFile, error) {
	var rows pgx.Rows
	var err error
	if folderID != nil {
		rows, err = s.DB.Pool.Query(ctx,
			`SELECT `+driveFileColumns+`
			 FROM drive_files
			 WHERE user_id = $1 AND tenant_id = $2 AND folder_id = $3 AND trashed = false
			 ORDER BY created_at DESC`,
			userID, tenantID, *folderID,
		)
	} else {
		rows, err = s.DB.Pool.Query(ctx,
			`SELECT `+driveFileColumns+`
			 FROM drive_files
			 WHERE user_id = $1 AND tenant_id = $2 AND folder_id IS NULL AND trashed = false
			 ORDER BY created_at DESC`,
			userID, tenantID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list drive files: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan drive file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// UpdateFile modifies an existing drive file.
func (s *DriveStore) UpdateFile(ctx context.Context, f *DriveFile) error {
	f.UpdatedAt = time.Now()
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_files SET
			folder_id = $4, encrypted_name = $5, encrypted_content_type = $6,
			ephemeral_pubkey = $7, encrypted_file_key = $8,
			starred = $9, trashed = $10, trashed_at = $11,
			updated_at = $12
		 WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3`,
		f.FileID, f.UserID, f.TenantID,
		f.FolderID, f.EncryptedName, f.EncryptedContentType,
		f.EphemeralPubkey, f.EncryptedFileKey,
		f.Starred, f.Trashed, f.TrashedAt,
		f.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update drive file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive file not found")
	}
	return nil
}

// DeleteFile removes a drive file by ID.
func (s *DriveStore) DeleteFile(ctx context.Context, userID, tenantID, fileID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM drive_files WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3`,
		fileID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete drive file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive file not found")
	}
	return nil
}

// --- Special queries ---

// ListStarred returns all starred, non-trashed files for a user.
func (s *DriveStore) ListStarred(ctx context.Context, userID, tenantID uuid.UUID) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFileColumns+`
		 FROM drive_files
		 WHERE user_id = $1 AND tenant_id = $2 AND starred = true AND trashed = false
		 ORDER BY updated_at DESC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list starred drive files: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan starred drive file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// ListTrashed returns all trashed files for a user.
func (s *DriveStore) ListTrashed(ctx context.Context, userID, tenantID uuid.UUID) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFileColumns+`
		 FROM drive_files
		 WHERE user_id = $1 AND tenant_id = $2 AND trashed = true
		 ORDER BY trashed_at DESC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list trashed drive files: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan trashed drive file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// TrashFile marks a file as trashed.
func (s *DriveStore) TrashFile(ctx context.Context, userID, tenantID, fileID uuid.UUID) error {
	now := time.Now()
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_files SET trashed = true, trashed_at = $4, updated_at = $4
		 WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3`,
		fileID, userID, tenantID, now,
	)
	if err != nil {
		return fmt.Errorf("trash drive file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive file not found")
	}
	return nil
}

// RestoreFile removes the trashed flag from a file.
func (s *DriveStore) RestoreFile(ctx context.Context, userID, tenantID, fileID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_files SET trashed = false, trashed_at = NULL, updated_at = now()
		 WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3`,
		fileID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("restore drive file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive file not found")
	}
	return nil
}

// PurgeOldTrashed returns and deletes all trashed files older than the given time.
// Callers should delete the associated blobs from R2 after this call.
func (s *DriveStore) PurgeOldTrashed(ctx context.Context, olderThan time.Time) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`DELETE FROM drive_files
		 WHERE trashed = true AND trashed_at < $1
		 RETURNING `+driveFileColumns,
		olderThan,
	)
	if err != nil {
		return nil, fmt.Errorf("purge old trashed drive files: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan purged drive file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// EmptyTrash deletes every trashed file row for the given user and returns
// the deleted rows so the caller can clean up R2 blobs. Atomic per-user
// version of PurgeOldTrashed without the time threshold.
func (s *DriveStore) EmptyTrash(ctx context.Context, userID, tenantID uuid.UUID) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`DELETE FROM drive_files
		 WHERE user_id = $1 AND tenant_id = $2 AND trashed = true
		 RETURNING `+driveFileColumns,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("empty trash: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan emptied trash file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// --- Share model and CRUD ---

// DriveShare represents a row in the drive_shares table.
type DriveShare struct {
	ShareID                   uuid.UUID  `db:"share_id"`
	// FileID is set for file-level shares and for auto-managed file
	// rewrap rows under a folder share. NULL for the conceptual folder
	// share row itself.
	FileID                    *uuid.UUID `db:"file_id"`
	// FolderID is set for the conceptual folder share row. NULL for
	// file-level shares (link/user) and for file rewrap rows under a
	// folder share.
	FolderID                  *uuid.UUID `db:"folder_id"`
	// ParentShareID is set on auto-managed file rewrap rows that hang
	// off a folder share. NULL for top-level rows.
	ParentShareID             *uuid.UUID `db:"parent_share_id"`
	UserID                    uuid.UUID  `db:"user_id"`
	TenantID                  uuid.UUID  `db:"tenant_id"`
	ShareType                 string     `db:"share_type"` // "link" or "user"
	LinkEncryptedFileKey      []byte     `db:"link_encrypted_file_key"`
	PasswordSalt              []byte     `db:"password_salt"`
	EncryptedBlob             []byte     `db:"encrypted_blob"`
	EncryptedName             []byte     `db:"encrypted_name"`
	EncryptedContentType      []byte     `db:"encrypted_content_type"`
	RecipientUserID           *uuid.UUID `db:"recipient_user_id"`
	RecipientEncryptedFileKey []byte     `db:"recipient_encrypted_file_key"`
	RecipientEphemeralPubkey  []byte     `db:"recipient_ephemeral_pubkey"`
	CanEdit                   bool       `db:"can_edit"`
	ExpiresAt                 *time.Time `db:"expires_at"`
	AccessCount               int        `db:"access_count"`
	CreatedAt                 time.Time  `db:"created_at"`
	// EncryptedLinkToken + LinkTokenEphPubkey: the link share token
	// wrapped under the owner's public encryption key. Lets the owner
	// retrieve the full share link later. NULL for user shares.
	EncryptedLinkToken        []byte     `db:"encrypted_link_token"`
	LinkTokenEphPubkey        []byte     `db:"link_token_eph_pubkey"`
}

const driveShareColumns = `share_id, file_id, folder_id, parent_share_id,
	user_id, tenant_id, share_type,
	link_encrypted_file_key, password_salt, encrypted_blob, encrypted_name, encrypted_content_type,
	recipient_user_id, recipient_encrypted_file_key, recipient_ephemeral_pubkey,
	can_edit, expires_at, access_count, created_at,
	encrypted_link_token, link_token_eph_pubkey`

func scanDriveShare(rows pgx.Rows) (*DriveShare, error) {
	s := &DriveShare{}
	if err := rows.Scan(
		&s.ShareID, &s.FileID, &s.FolderID, &s.ParentShareID,
		&s.UserID, &s.TenantID, &s.ShareType,
		&s.LinkEncryptedFileKey, &s.PasswordSalt, &s.EncryptedBlob, &s.EncryptedName, &s.EncryptedContentType,
		&s.RecipientUserID, &s.RecipientEncryptedFileKey, &s.RecipientEphemeralPubkey,
		&s.CanEdit, &s.ExpiresAt, &s.AccessCount, &s.CreatedAt,
		&s.EncryptedLinkToken, &s.LinkTokenEphPubkey,
	); err != nil {
		return nil, err
	}
	return s, nil
}

// CreateShare inserts a new drive share record.
func (s *DriveStore) CreateShare(ctx context.Context, share *DriveShare) error {
	if share.ShareID == uuid.Nil {
		share.ShareID = uuid.New()
	}
	share.CreatedAt = time.Now()
	// User file shares (file_id set, parent_share_id NULL, recipient set)
	// are idempotent on (file_id, recipient_user_id) — re-sharing the
	// same file with the same recipient updates the existing rewrap
	// instead of creating a parallel row. Link shares and other shapes
	// fall through to a plain insert.
	if share.ShareType == "user" && share.FileID != nil && share.ParentShareID == nil && share.RecipientUserID != nil {
		_, err := s.DB.Pool.Exec(ctx,
			`INSERT INTO drive_shares (share_id, file_id, folder_id, parent_share_id,
				user_id, tenant_id, share_type,
				link_encrypted_file_key, password_salt, encrypted_blob, encrypted_name, encrypted_content_type,
				recipient_user_id, recipient_encrypted_file_key, recipient_ephemeral_pubkey,
				can_edit, expires_at, access_count, created_at,
				encrypted_link_token, link_token_eph_pubkey)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			 ON CONFLICT (file_id, recipient_user_id)
			     WHERE share_type = 'user'
			       AND parent_share_id IS NULL
			       AND file_id IS NOT NULL
			       AND recipient_user_id IS NOT NULL
			     DO UPDATE SET
			       recipient_encrypted_file_key = EXCLUDED.recipient_encrypted_file_key,
			       recipient_ephemeral_pubkey   = EXCLUDED.recipient_ephemeral_pubkey,
			       can_edit                     = EXCLUDED.can_edit,
			       expires_at                   = EXCLUDED.expires_at`,
			share.ShareID, share.FileID, share.FolderID, share.ParentShareID,
			share.UserID, share.TenantID, share.ShareType,
			share.LinkEncryptedFileKey, share.PasswordSalt, share.EncryptedBlob, share.EncryptedName, share.EncryptedContentType,
			share.RecipientUserID, share.RecipientEncryptedFileKey, share.RecipientEphemeralPubkey,
			share.CanEdit, share.ExpiresAt, share.AccessCount, share.CreatedAt,
			share.EncryptedLinkToken, share.LinkTokenEphPubkey,
		)
		if err != nil {
			return fmt.Errorf("create drive share: %w", err)
		}
		return nil
	}

	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO drive_shares (share_id, file_id, folder_id, parent_share_id,
			user_id, tenant_id, share_type,
			link_encrypted_file_key, password_salt, encrypted_blob, encrypted_name, encrypted_content_type,
			recipient_user_id, recipient_encrypted_file_key, recipient_ephemeral_pubkey,
			can_edit, expires_at, access_count, created_at,
			encrypted_link_token, link_token_eph_pubkey)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		share.ShareID, share.FileID, share.FolderID, share.ParentShareID,
		share.UserID, share.TenantID, share.ShareType,
		share.LinkEncryptedFileKey, share.PasswordSalt, share.EncryptedBlob, share.EncryptedName, share.EncryptedContentType,
		share.RecipientUserID, share.RecipientEncryptedFileKey, share.RecipientEphemeralPubkey,
		share.CanEdit, share.ExpiresAt, share.AccessCount, share.CreatedAt,
		share.EncryptedLinkToken, share.LinkTokenEphPubkey,
	)
	if err != nil {
		return fmt.Errorf("create drive share: %w", err)
	}
	return nil
}

// GetShare retrieves a share by ID without user scoping (public access for link shares).
func (s *DriveStore) GetShare(ctx context.Context, shareID uuid.UUID) (*DriveShare, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveShareColumns+`
		 FROM drive_shares
		 WHERE share_id = $1`,
		shareID,
	)
	if err != nil {
		return nil, fmt.Errorf("get drive share: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("drive share not found")
	}
	return scanDriveShare(rows)
}

// ListSharesByFile returns all DIRECT shares for a file, scoped to the
// file owner. Auto-managed file rewrap rows from folder shares
// (parent_share_id IS NOT NULL) are excluded — those aren't user-visible
// individual shares, they're plumbing under a parent folder share.
func (s *DriveStore) ListSharesByFile(ctx context.Context, userID, tenantID, fileID uuid.UUID) ([]*DriveShare, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveShareColumns+`
		 FROM drive_shares
		 WHERE file_id = $1 AND user_id = $2 AND tenant_id = $3
		   AND parent_share_id IS NULL
		 ORDER BY created_at DESC`,
		fileID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list drive shares: %w", err)
	}
	defer rows.Close()

	var shares []*DriveShare
	for rows.Next() {
		sh, err := scanDriveShare(rows)
		if err != nil {
			return nil, fmt.Errorf("scan drive share: %w", err)
		}
		shares = append(shares, sh)
	}
	return shares, nil
}

// ListSharesByFolder returns all link shares for a folder from drive_shares,
// scoped to the folder owner. Used by the "Active shares" UI.
func (s *DriveStore) ListSharesByFolder(ctx context.Context, userID, tenantID, folderID uuid.UUID) ([]*DriveShare, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveShareColumns+`
		 FROM drive_shares
		 WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3
		   AND share_type = 'link'
		 ORDER BY created_at DESC`,
		folderID, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list drive shares by folder: %w", err)
	}
	defer rows.Close()

	var shares []*DriveShare
	for rows.Next() {
		sh, err := scanDriveShare(rows)
		if err != nil {
			return nil, fmt.Errorf("scan drive share: %w", err)
		}
		shares = append(shares, sh)
	}
	return shares, nil
}

// DeleteShare removes a share by ID, scoped to the share owner.
func (s *DriveStore) DeleteShare(ctx context.Context, userID, tenantID, shareID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM drive_shares WHERE share_id = $1 AND user_id = $2 AND tenant_id = $3`,
		shareID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete drive share: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drive share not found")
	}
	return nil
}

// IncrementShareAccess atomically increments the access_count for a share.
func (s *DriveStore) IncrementShareAccess(ctx context.Context, shareID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_shares SET access_count = access_count + 1 WHERE share_id = $1`,
		shareID,
	)
	if err != nil {
		return fmt.Errorf("increment share access: %w", err)
	}
	return nil
}

// SharedDriveFile is a drive file as seen by a recipient via a user share.
// The file's encryption keys are SWAPPED — instead of the owner's
// ephemeral_pubkey + encrypted_file_key (which the recipient can't unwrap),
// the recipient sees the keys from the share row that were re-wrapped for
// their pubkey at share-creation time.
type SharedDriveFile struct {
	*DriveFile
	// Address of the user who shared the file (display only — null when
	// the share row references a deleted user).
	OwnerAddress string
}

// ListSharedWithUser returns all files shared with a given recipient user,
// with the encryption keys swapped to the share row's recipient-wrapped
// values so the recipient's private key can decrypt them.
func (s *DriveStore) ListSharedWithUser(ctx context.Context, recipientUserID, tenantID uuid.UUID) ([]*SharedDriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT f.file_id, f.user_id, f.tenant_id, f.folder_id,
		        f.encrypted_name, f.encrypted_content_type, f.size_bytes, f.original_size_bytes, f.blob_ref,
		        s.recipient_ephemeral_pubkey, s.recipient_encrypted_file_key, f.fck_wrapped_message_key, f.epoch, f.encryption_format,
		        f.chunk_count,
		        f.starred, f.trashed, f.trashed_at,
		        f.created_at, f.updated_at,
		        COALESCE(u.address, '')
		 FROM drive_files f
		 INNER JOIN drive_shares s ON f.file_id = s.file_id
		 LEFT JOIN users u ON u.user_id = f.user_id
		 WHERE s.recipient_user_id = $1 AND s.tenant_id = $2
		   AND s.share_type = 'user'
		   AND (s.expires_at IS NULL OR s.expires_at > now())
		 ORDER BY s.created_at DESC`,
		recipientUserID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list shared with user: %w", err)
	}
	defer rows.Close()

	var out []*SharedDriveFile
	for rows.Next() {
		f := &DriveFile{}
		var ownerAddr string
		if err := rows.Scan(
			&f.FileID, &f.UserID, &f.TenantID, &f.FolderID,
			&f.EncryptedName, &f.EncryptedContentType, &f.SizeBytes, &f.OriginalSizeBytes, &f.BlobRef,
			&f.EphemeralPubkey, &f.EncryptedFileKey, &f.FCKWrappedMessageKey, &f.Epoch, &f.EncryptionFormat,
			&f.ChunkCount,
			&f.Starred, &f.Trashed, &f.TrashedAt,
			&f.CreatedAt, &f.UpdatedAt,
			&ownerAddr,
		); err != nil {
			return nil, fmt.Errorf("scan shared drive file: %w", err)
		}
		out = append(out, &SharedDriveFile{DriveFile: f, OwnerAddress: ownerAddr})
	}
	return out, nil
}

// GetSharedFile returns a single shared file row by file_id, scoped to a
// recipient user via the share record. Used by the download path so a
// recipient can fetch a file someone shared with them. The returned file
// carries the SHARE's recipient-wrapped keys, not the owner's.
func (s *DriveStore) GetSharedFile(ctx context.Context, recipientUserID, tenantID, fileID uuid.UUID) (*SharedDriveFile, error) {
	row := s.DB.Pool.QueryRow(ctx,
		`SELECT f.file_id, f.user_id, f.tenant_id, f.folder_id,
		        f.encrypted_name, f.encrypted_content_type, f.size_bytes, f.original_size_bytes, f.blob_ref,
		        s.recipient_ephemeral_pubkey, s.recipient_encrypted_file_key, f.fck_wrapped_message_key, f.epoch, f.encryption_format,
		        f.chunk_count,
		        f.starred, f.trashed, f.trashed_at,
		        f.created_at, f.updated_at,
		        COALESCE(u.address, '')
		 FROM drive_files f
		 INNER JOIN drive_shares s ON f.file_id = s.file_id
		 LEFT JOIN users u ON u.user_id = f.user_id
		 WHERE f.file_id = $1
		   AND s.recipient_user_id = $2 AND s.tenant_id = $3
		   AND s.share_type = 'user'
		   AND (s.expires_at IS NULL OR s.expires_at > now())
		 LIMIT 1`,
		fileID, recipientUserID, tenantID,
	)
	f := &DriveFile{}
	var ownerAddr string
	if err := row.Scan(
		&f.FileID, &f.UserID, &f.TenantID, &f.FolderID,
		&f.EncryptedName, &f.EncryptedContentType, &f.SizeBytes, &f.OriginalSizeBytes, &f.BlobRef,
		&f.EphemeralPubkey, &f.EncryptedFileKey, &f.FCKWrappedMessageKey, &f.Epoch, &f.EncryptionFormat,
		&f.ChunkCount,
		&f.Starred, &f.Trashed, &f.TrashedAt,
		&f.CreatedAt, &f.UpdatedAt,
		&ownerAddr,
	); err != nil {
		return nil, fmt.Errorf("get shared file: %w", err)
	}
	return &SharedDriveFile{DriveFile: f, OwnerAddress: ownerAddr}, nil
}

// GetFileByID retrieves a drive file by ID without user scoping.
// Used for shared file access where ownership is verified via the share record.
func (s *DriveStore) GetFileByID(ctx context.Context, fileID uuid.UUID) (*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFileColumns+`
		 FROM drive_files
		 WHERE file_id = $1`,
		fileID,
	)
	if err != nil {
		return nil, fmt.Errorf("get drive file by id: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("drive file not found")
	}
	return scanDriveFile(rows)
}

// AddFileSize atomically adds bytes to a file's size_bytes. Used during
// chunked uploads to accumulate the total encrypted size across chunks.
func (s *DriveStore) AddFileSize(ctx context.Context, fileID uuid.UUID, additionalBytes int64) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE drive_files SET size_bytes = size_bytes + $2, updated_at = now()
		 WHERE file_id = $1`,
		fileID, additionalBytes,
	)
	if err != nil {
		return fmt.Errorf("add file size: %w", err)
	}
	return nil
}

// GetStorageUsed returns the total bytes used and file count for a user.
func (s *DriveStore) GetStorageUsed(ctx context.Context, userID, tenantID uuid.UUID) (int64, int, error) {
	var totalBytes int64
	var fileCount int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes), 0), COUNT(*)
		 FROM drive_files
		 WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	).Scan(&totalBytes, &fileCount)
	if err != nil {
		return 0, 0, fmt.Errorf("get drive storage used: %w", err)
	}
	return totalBytes, fileCount, nil
}


// SharedFolderEntry is a folder appearing in the recipient's "Shared
// with me" view (top-level) or as a sub-folder of a shared folder.
type SharedFolderEntry struct {
	*DriveFolder
	OwnerAddress        string
	CanEdit             bool
	JoinedEpoch         int
	PastEpochAccess     bool
	EncryptedName       []byte
	WrappedFCK          []byte
	WrappedFCKEphPubkey []byte
}

// ── Epoch-based Folder Sharing ─────────────────────────────────
//
// Post-migration-077, folder sharing uses an epoch-keyed FCK model:
//   - Each folder has a current_epoch counter (starts at 0).
//   - Each epoch has its own random 32-byte FCK.
//   - The FCK for each epoch is wrapped under each member's X25519
//     pubkey and stored in drive_folder_epoch_keys.
//   - Folder names are encrypted under each epoch's FCK and stored
//     in drive_folder_epoch_names.
//   - Membership is tracked in drive_folder_shares (separate from
//     the per-file drive_shares table).
//   - Every member-set change advances the epoch counter and
//     generates a fresh FCK, giving post-compromise security on
//     recipient removal.

// EpochKeyWrap is one recipient's wrap of an epoch's FCK.
type EpochKeyWrap struct {
	RecipientUserID     uuid.UUID
	WrappedFCK          []byte
	WrappedFCKEphPubkey []byte
}

// FCKFileWrapInput is one entry in a batch of file-message-key wraps
// under a folder's FCK. Used at folder-share creation time to backfill
// every file in the tree.
type FCKFileWrapInput struct {
	FileID               uuid.UUID
	FCKWrappedMessageKey []byte
	Epoch                int
}

// ── Folder epoch key queries ──────────────────────────────────

// GetFolderEpochKeysForUser returns all epoch FCK wraps for a folder
// that a given user has access to. Used at navigation time so the
// client can unwrap each epoch's FCK and decrypt files.
func (s *DriveStore) GetFolderEpochKeysForUser(
	ctx context.Context,
	folderID, recipientUserID, tenantID uuid.UUID,
) ([]DriveFolderEpochKey, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT folder_id, epoch, recipient_user_id, tenant_id,
		        wrapped_fck, wrapped_fck_eph_pubkey, created_at
		   FROM drive_folder_epoch_keys
		  WHERE folder_id = $1 AND recipient_user_id = $2 AND tenant_id = $3
		  ORDER BY epoch ASC`,
		folderID, recipientUserID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get folder epoch keys: %w", err)
	}
	defer rows.Close()

	var out []DriveFolderEpochKey
	for rows.Next() {
		var ek DriveFolderEpochKey
		if err := rows.Scan(
			&ek.FolderID, &ek.Epoch, &ek.RecipientUserID, &ek.TenantID,
			&ek.WrappedFCK, &ek.WrappedFCKEphPubkey, &ek.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan epoch key: %w", err)
		}
		out = append(out, ek)
	}
	return out, nil
}

// GetFolderEpochName returns the encrypted name for a folder at a
// given epoch (or the current epoch if epoch < 0).
func (s *DriveStore) GetFolderEpochName(
	ctx context.Context,
	folderID uuid.UUID,
	epoch int,
) ([]byte, error) {
	q := `SELECT encrypted_name FROM drive_folder_epoch_names
	      WHERE folder_id = $1 AND epoch = $2`
	if epoch < 0 {
		q = `SELECT encrypted_name FROM drive_folder_epoch_names
		     WHERE folder_id = $1
		       AND epoch = (SELECT current_epoch FROM drive_folders WHERE folder_id = $1)`
	}
	var enc []byte
	err := s.DB.Pool.QueryRow(ctx, q, folderID, epoch).Scan(&enc)
	if err != nil {
		return nil, fmt.Errorf("get folder epoch name: %w", err)
	}
	return enc, nil
}

// ── Folder share membership ───────────────────────────────────

// ListFolderShareMembers returns all active share members for a folder.
func (s *DriveStore) ListFolderShareMembers(
	ctx context.Context,
	folderID, tenantID uuid.UUID,
) ([]DriveFolderShareMember, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT folder_id, recipient_user_id, tenant_id, owner_user_id,
		        joined_epoch, past_epoch_access, can_edit, expires_at, created_at
		   FROM drive_folder_shares
		  WHERE folder_id = $1 AND tenant_id = $2
		    AND (expires_at IS NULL OR expires_at > now())
		  ORDER BY created_at`,
		folderID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list folder share members: %w", err)
	}
	defer rows.Close()

	var out []DriveFolderShareMember
	for rows.Next() {
		var m DriveFolderShareMember
		if err := rows.Scan(
			&m.FolderID, &m.RecipientUserID, &m.TenantID, &m.OwnerUserID,
			&m.JoinedEpoch, &m.PastEpochAccess, &m.CanEdit, &m.ExpiresAt, &m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan folder share member: %w", err)
		}
		out = append(out, m)
	}
	return out, nil
}

// HasFolderShareAccess returns true if the user has any active folder
// share granting them access to folderID (or any of its ancestors).
func (s *DriveStore) HasFolderShareAccess(
	ctx context.Context,
	recipientUserID, tenantID, folderID uuid.UUID,
) (bool, error) {
	var count int
	err := s.DB.Pool.QueryRow(ctx,
		`WITH RECURSIVE ancestors AS (
			SELECT folder_id, parent_id FROM drive_folders
			WHERE folder_id = $1 AND tenant_id = $2
			UNION ALL
			SELECT f.folder_id, f.parent_id FROM drive_folders f
			INNER JOIN ancestors a ON f.folder_id = a.parent_id
			WHERE f.tenant_id = $2
		)
		SELECT COUNT(*) FROM drive_folder_shares
		WHERE folder_id IN (SELECT folder_id FROM ancestors)
		  AND recipient_user_id = $3 AND tenant_id = $2
		  AND (expires_at IS NULL OR expires_at > now())`,
		folderID, tenantID, recipientUserID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check folder share access: %w", err)
	}
	return count > 0, nil
}

// ── Epoch advance + share creation ────────────────────────────

// ShareFolderEpochInput holds all the data needed for an epoch advance
// when sharing a folder: the new epoch's key wraps for each member,
// the encrypted folder name under the new FCK, and optionally per-file
// FCK wraps for backfilling existing files.
type ShareFolderEpochInput struct {
	FolderID        uuid.UUID
	OwnerUserID     uuid.UUID
	TenantID        uuid.UUID
	// NewEpochKeyWraps: one entry per member (owner + all recipients)
	// with their wrap of the new epoch's FCK.
	NewEpochKeyWraps []EpochKeyWrap
	// EncryptedName: folder name encrypted under the new epoch's FCK.
	EncryptedName []byte
	// FileWraps: per-file FCK wraps under the new epoch's FCK. Only
	// needed on first share (epoch 0 → 1) to backfill existing files.
	// Empty on subsequent epoch advances (new files are wrapped at
	// upload time).
	FileWraps []FCKFileWrapInput
	// SubFolderNames: sub-folder names encrypted under the new FCK.
	// Populated at share creation so the recipient can read sub-folder
	// names. Each entry is (folder_id, encrypted_name).
	SubFolderNames []DriveFolderEpochName
}

// AdvanceFolderEpoch atomically advances a folder's epoch counter and
// writes the new epoch's key wraps + encrypted name. Used for both
// adding and removing members.
func (s *DriveStore) AdvanceFolderEpoch(ctx context.Context, in ShareFolderEpochInput) (newEpoch int, err error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin epoch advance tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Atomically increment current_epoch and return the new value.
	var epoch int
	err = tx.QueryRow(ctx,
		`UPDATE drive_folders
		    SET current_epoch = current_epoch + 1, updated_at = now()
		  WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3
		  RETURNING current_epoch`,
		in.FolderID, in.OwnerUserID, in.TenantID,
	).Scan(&epoch)
	if err != nil {
		return 0, fmt.Errorf("advance epoch: %w", err)
	}

	// Insert key wraps for every member at the new epoch.
	for _, kw := range in.NewEpochKeyWraps {
		_, err := tx.Exec(ctx,
			`INSERT INTO drive_folder_epoch_keys
				(folder_id, epoch, recipient_user_id, tenant_id, wrapped_fck, wrapped_fck_eph_pubkey)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			in.FolderID, epoch, kw.RecipientUserID, in.TenantID,
			kw.WrappedFCK, kw.WrappedFCKEphPubkey,
		)
		if err != nil {
			return 0, fmt.Errorf("insert epoch key wrap for %s: %w", kw.RecipientUserID, err)
		}
	}

	// Insert the encrypted folder name for this epoch.
	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folder_epoch_names (folder_id, epoch, encrypted_name)
		 VALUES ($1, $2, $3)`,
		in.FolderID, epoch, in.EncryptedName,
	)
	if err != nil {
		return 0, fmt.Errorf("insert epoch name: %w", err)
	}

	// Sub-folder names under the new FCK (if any).
	for _, sfn := range in.SubFolderNames {
		_, err := tx.Exec(ctx,
			`INSERT INTO drive_folder_epoch_names (folder_id, epoch, encrypted_name)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (folder_id, epoch) DO UPDATE SET encrypted_name = EXCLUDED.encrypted_name`,
			sfn.FolderID, epoch, sfn.EncryptedName,
		)
		if err != nil {
			return 0, fmt.Errorf("insert subfolder epoch name %s: %w", sfn.FolderID, err)
		}
	}

	// Backfill file wraps (first share only — on subsequent shares the
	// files are already wrapped at upload time).
	for _, fw := range in.FileWraps {
		_, err := tx.Exec(ctx,
			`UPDATE drive_files
			    SET fck_wrapped_message_key = $1, epoch = $2, updated_at = now()
			  WHERE file_id = $3 AND user_id = $4 AND tenant_id = $5`,
			fw.FCKWrappedMessageKey, epoch, fw.FileID, in.OwnerUserID, in.TenantID,
		)
		if err != nil {
			return 0, fmt.Errorf("backfill file wrap %s: %w", fw.FileID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit epoch advance: %w", err)
	}
	return epoch, nil
}

// AddFolderShareMember inserts a new member into drive_folder_shares.
// Caller must advance the epoch first (via AdvanceFolderEpoch), then
// call this to record the membership.
func (s *DriveStore) AddFolderShareMember(ctx context.Context, m DriveFolderShareMember) error {
	m.CreatedAt = time.Now()
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO drive_folder_shares
			(folder_id, recipient_user_id, tenant_id, owner_user_id,
			 joined_epoch, past_epoch_access, can_edit, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (folder_id, recipient_user_id) DO UPDATE SET
		   joined_epoch = EXCLUDED.joined_epoch,
		   past_epoch_access = EXCLUDED.past_epoch_access,
		   can_edit = EXCLUDED.can_edit,
		   expires_at = EXCLUDED.expires_at`,
		m.FolderID, m.RecipientUserID, m.TenantID, m.OwnerUserID,
		m.JoinedEpoch, m.PastEpochAccess, m.CanEdit, m.ExpiresAt, m.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("add folder share member: %w", err)
	}
	return nil
}

// BackfillEpochKeysForMember inserts wraps of past epoch FCKs for a
// newly-added member who has past_epoch_access = true. The caller
// client computes these by unwrapping the owner's wraps of past FCKs
// and re-wrapping for the new member.
func (s *DriveStore) BackfillEpochKeysForMember(
	ctx context.Context,
	folderID, recipientUserID, tenantID uuid.UUID,
	wraps []EpochKeyWrap,
	fromEpoch, toEpoch int,
) error {
	for epoch := fromEpoch; epoch < toEpoch; epoch++ {
		found := false
		for _, kw := range wraps {
			if !found {
				_, err := s.DB.Pool.Exec(ctx,
					`INSERT INTO drive_folder_epoch_keys
						(folder_id, epoch, recipient_user_id, tenant_id, wrapped_fck, wrapped_fck_eph_pubkey)
					 VALUES ($1, $2, $3, $4, $5, $6)
					 ON CONFLICT DO NOTHING`,
					folderID, epoch, recipientUserID, tenantID,
					kw.WrappedFCK, kw.WrappedFCKEphPubkey,
				)
				if err != nil {
					return fmt.Errorf("backfill epoch %d key: %w", epoch, err)
				}
				found = true
				break
			}
		}
	}
	return nil
}

// RemoveFolderShareMember deletes a member from drive_folder_shares
// and hard-deletes all their epoch key wraps (defense in depth).
// Caller must advance the epoch first.
func (s *DriveStore) RemoveFolderShareMember(
	ctx context.Context,
	folderID, recipientUserID, tenantID uuid.UUID,
) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin remove member tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`DELETE FROM drive_folder_shares
		 WHERE folder_id = $1 AND recipient_user_id = $2 AND tenant_id = $3`,
		folderID, recipientUserID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete folder share member: %w", err)
	}

	// Hard-delete all the removed member's epoch key wraps so they
	// can never re-fetch them via the API.
	_, err = tx.Exec(ctx,
		`DELETE FROM drive_folder_epoch_keys
		 WHERE folder_id = $1 AND recipient_user_id = $2 AND tenant_id = $3`,
		folderID, recipientUserID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete epoch keys for removed member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit remove member: %w", err)
	}
	return nil
}

// ── Shared folder contents queries ────────────────────────────

// ListSharedFolderContents returns files + sub-folders inside a shared
// folder. Files come directly from drive_files (no per-file rewrap
// rows — recipients decrypt via FCK). Sub-folders come from
// drive_folders with their epoch name joined in.
//
// The caller must verify access via HasFolderShareAccess first.
func (s *DriveStore) ListSharedFolderContents(
	ctx context.Context,
	recipientUserID, tenantID, folderID uuid.UUID,
) ([]*SharedDriveFile, []*SharedFolderEntry, error) {
	// Files: direct from drive_files, no share-row join needed.
	// Recipients use the FCK they cached at navigation time.
	fileRows, err := s.DB.Pool.Query(ctx,
		`SELECT f.file_id, f.user_id, f.tenant_id, f.folder_id,
		        f.encrypted_name, f.encrypted_content_type, f.size_bytes, f.original_size_bytes, f.blob_ref,
		        f.ephemeral_pubkey, f.encrypted_file_key, f.fck_wrapped_message_key, f.epoch, f.encryption_format,
		        f.chunk_count,
		        f.starred, f.trashed, f.trashed_at,
		        f.created_at, f.updated_at,
		        COALESCE(u.address, '')
		   FROM drive_files f
		   LEFT JOIN users u ON u.user_id = f.user_id
		  WHERE f.folder_id = $1
		    AND f.tenant_id = $2
		    AND f.trashed = false
		  ORDER BY f.created_at DESC`,
		folderID, tenantID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("list shared folder files: %w", err)
	}
	defer fileRows.Close()

	var files []*SharedDriveFile
	for fileRows.Next() {
		f := &DriveFile{}
		var ownerAddr string
		if err := fileRows.Scan(
			&f.FileID, &f.UserID, &f.TenantID, &f.FolderID,
			&f.EncryptedName, &f.EncryptedContentType, &f.SizeBytes, &f.OriginalSizeBytes, &f.BlobRef,
			&f.EphemeralPubkey, &f.EncryptedFileKey, &f.FCKWrappedMessageKey, &f.Epoch, &f.EncryptionFormat,
			&f.ChunkCount,
			&f.Starred, &f.Trashed, &f.TrashedAt,
			&f.CreatedAt, &f.UpdatedAt,
			&ownerAddr,
		); err != nil {
			return nil, nil, fmt.Errorf("scan shared folder file: %w", err)
		}
		files = append(files, &SharedDriveFile{DriveFile: f, OwnerAddress: ownerAddr})
	}

	// Sub-folders: join to epoch_names for the folder's current epoch
	// so the recipient can decrypt the sub-folder name with their
	// cached FCK.
	folderRows, err := s.DB.Pool.Query(ctx,
		`SELECT df.folder_id, df.user_id, df.tenant_id, df.parent_id,
		        df.current_epoch, df.created_at, df.updated_at,
		        COALESCE(u.address, ''),
		        en.encrypted_name
		   FROM drive_folders df
		   LEFT JOIN drive_folder_epoch_names en
		     ON en.folder_id = df.folder_id AND en.epoch = df.current_epoch
		   LEFT JOIN users u ON u.user_id = df.user_id
		  WHERE df.parent_id = $1 AND df.tenant_id = $2
		  ORDER BY df.created_at`,
		folderID, tenantID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("list shared folder subfolders: %w", err)
	}
	defer folderRows.Close()

	var folders []*SharedFolderEntry
	for folderRows.Next() {
		f := &DriveFolder{}
		var ownerAddr string
		var encName []byte
		if err := folderRows.Scan(
			&f.FolderID, &f.UserID, &f.TenantID, &f.ParentID,
			&f.CurrentEpoch, &f.CreatedAt, &f.UpdatedAt,
			&ownerAddr, &encName,
		); err != nil {
			return nil, nil, fmt.Errorf("scan shared subfolder: %w", err)
		}
		folders = append(folders, &SharedFolderEntry{
			DriveFolder:   f,
			OwnerAddress:  ownerAddr,
			EncryptedName: encName,
		})
	}

	return files, folders, nil
}

// ── Share root lookup ─────────────────────────────────────────

// GetShareRootForFolder walks up from folderID through the parent
// chain and returns the nearest ancestor (or self) that is a share
// root (has a row in drive_folder_shares). Returns the share root's
// folder_id + current_epoch, or uuid.Nil if no share root exists.
func (s *DriveStore) GetShareRootForFolder(
	ctx context.Context,
	tenantID, folderID uuid.UUID,
) (rootFolderID uuid.UUID, currentEpoch int, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`WITH RECURSIVE ancestors AS (
			SELECT folder_id, parent_id, 0 AS depth
			  FROM drive_folders WHERE folder_id = $1 AND tenant_id = $2
			UNION ALL
			SELECT df.folder_id, df.parent_id, a.depth + 1
			  FROM drive_folders df
			 INNER JOIN ancestors a ON df.folder_id = a.parent_id
			 WHERE df.tenant_id = $2
		)
		SELECT a.folder_id, df.current_epoch
		  FROM ancestors a
		  JOIN drive_folders df ON df.folder_id = a.folder_id
		 WHERE EXISTS (
		   SELECT 1 FROM drive_folder_shares fs WHERE fs.folder_id = a.folder_id
		 )
		 ORDER BY a.depth ASC
		 LIMIT 1`,
		folderID, tenantID,
	).Scan(&rootFolderID, &currentEpoch)
	if err != nil {
		return uuid.Nil, 0, err // pgx.ErrNoRows if no share root
	}
	return rootFolderID, currentEpoch, nil
}

// ── Write permission helpers ──────────────────────────────────

// CanWriteToFolder reports whether a user can upload files or create
// sub-folders inside a folder. True if either:
//   - They own the folder, OR
//   - They have a folder share with can_edit=true covering this
//     folder or any ancestor.
func (s *DriveStore) CanWriteToFolder(
	ctx context.Context,
	userID, tenantID, folderID uuid.UUID,
) (canWrite bool, ownerUserID uuid.UUID, err error) {
	// Owner check first.
	var owner uuid.UUID
	row := s.DB.Pool.QueryRow(ctx,
		`SELECT user_id FROM drive_folders WHERE folder_id = $1 AND tenant_id = $2`,
		folderID, tenantID,
	)
	if err := row.Scan(&owner); err != nil {
		return false, uuid.Nil, fmt.Errorf("lookup folder owner: %w", err)
	}
	if owner == userID {
		return true, owner, nil
	}

	var count int
	err = s.DB.Pool.QueryRow(ctx,
		`WITH RECURSIVE ancestors AS (
			SELECT folder_id, parent_id FROM drive_folders
			WHERE folder_id = $1 AND tenant_id = $2
			UNION ALL
			SELECT f.folder_id, f.parent_id FROM drive_folders f
			INNER JOIN ancestors a ON f.folder_id = a.parent_id
			WHERE f.tenant_id = $2
		)
		SELECT COUNT(*) FROM drive_folder_shares
		WHERE folder_id IN (SELECT folder_id FROM ancestors)
		  AND recipient_user_id = $3 AND tenant_id = $2
		  AND can_edit = true
		  AND (expires_at IS NULL OR expires_at > now())`,
		folderID, tenantID, userID,
	).Scan(&count)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("check folder write access: %w", err)
	}
	return count > 0, owner, nil
}

// FolderShareParty represents one party (owner or recipient) of a
// shared folder.
type FolderShareParty struct {
	UserID       uuid.UUID
	Address      string
	PublicKey    []byte
	PublicKeyKEM []byte
}

// GetFolderShareParties returns the owner + every recipient with
// active access to a shared folder.
func (s *DriveStore) GetFolderShareParties(
	ctx context.Context,
	folderID, tenantID uuid.UUID,
) (owner FolderShareParty, recipients []FolderShareParty, err error) {
	row := s.DB.Pool.QueryRow(ctx,
		`SELECT u.user_id, u.address, u.public_key_encryption, u.public_key_kem
		   FROM drive_folders f
		   JOIN users u ON u.user_id = f.user_id
		  WHERE f.folder_id = $1 AND f.tenant_id = $2`,
		folderID, tenantID,
	)
	if err := row.Scan(&owner.UserID, &owner.Address, &owner.PublicKey, &owner.PublicKeyKEM); err != nil {
		return owner, nil, fmt.Errorf("lookup folder owner: %w", err)
	}

	rows, err := s.DB.Pool.Query(ctx,
		`SELECT u.user_id, u.address, u.public_key_encryption, u.public_key_kem
		   FROM drive_folder_shares fs
		   JOIN users u ON u.user_id = fs.recipient_user_id
		  WHERE fs.folder_id = $1 AND fs.tenant_id = $2
		    AND (fs.expires_at IS NULL OR fs.expires_at > now())`,
		folderID, tenantID,
	)
	if err != nil {
		return owner, nil, fmt.Errorf("list folder share parties: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p FolderShareParty
		if err := rows.Scan(&p.UserID, &p.Address, &p.PublicKey, &p.PublicKeyKEM); err != nil {
			return owner, nil, fmt.Errorf("scan party: %w", err)
		}
		recipients = append(recipients, p)
	}
	return owner, recipients, nil
}

// ── Shared folder upload (Phase 2 write path) ─────────────────

// CreateFileViaSharedFolder inserts a new file row owned by the
// original folder owner. The file's epoch is set to the folder's
// current_epoch, and fck_wrapped_message_key is populated so all
// recipients can decrypt via FCK.
func (s *DriveStore) CreateFileViaSharedFolder(
	ctx context.Context,
	file *DriveFile,
) error {
	if file.FileID == uuid.Nil {
		file.FileID = uuid.New()
	}
	now := time.Now()
	file.CreatedAt = now
	file.UpdatedAt = now

	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO drive_files (file_id, user_id, tenant_id, folder_id,
			encrypted_name, encrypted_content_type, size_bytes, original_size_bytes, blob_ref,
			ephemeral_pubkey, encrypted_file_key, fck_wrapped_message_key, epoch, encryption_format,
			chunk_count,
			starred, trashed, trashed_at,
			created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		file.FileID, file.UserID, file.TenantID, file.FolderID,
		file.EncryptedName, file.EncryptedContentType, file.SizeBytes, file.OriginalSizeBytes, file.BlobRef,
		file.EphemeralPubkey, file.EncryptedFileKey, file.FCKWrappedMessageKey, file.Epoch, file.EncryptionFormat,
		file.ChunkCount,
		file.Starred, file.Trashed, file.TrashedAt,
		file.CreatedAt, file.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create shared folder file: %w", err)
	}
	return nil
}

// CreateFolderViaSharedFolder creates a sub-folder inside a shared
// folder. The new folder is owned by the original folder owner and
// its name is encrypted under the current epoch's FCK.
func (s *DriveStore) CreateFolderViaSharedFolder(
	ctx context.Context,
	folder *DriveFolder,
	encryptedName []byte,
) error {
	if folder.FolderID == uuid.Nil {
		folder.FolderID = uuid.New()
	}
	now := time.Now()
	folder.CreatedAt = now
	folder.UpdatedAt = now
	folder.CurrentEpoch = 0

	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin create shared subfolder tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folders (folder_id, user_id, tenant_id, parent_id,
			current_epoch, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		folder.FolderID, folder.UserID, folder.TenantID, folder.ParentID,
		folder.CurrentEpoch, folder.CreatedAt, folder.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert shared subfolder: %w", err)
	}

	// The sub-folder's name is encrypted under the SHARE ROOT's
	// current epoch FCK. We store it in drive_folder_epoch_names
	// at epoch = the share root's current_epoch, but keyed by
	// THIS sub-folder's folder_id.
	// The caller passes the already-computed encrypted name.
	// We use epoch 0 for this sub-folder's own epoch counter
	// (sub-folders start at 0 and don't independently advance).
	_, err = tx.Exec(ctx,
		`INSERT INTO drive_folder_epoch_names (folder_id, epoch, encrypted_name)
		 VALUES ($1, 0, $2)`,
		folder.FolderID, encryptedName,
	)
	if err != nil {
		return fmt.Errorf("insert subfolder epoch name: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit create shared subfolder: %w", err)
	}
	return nil
}

// ── Recursive file/folder listing helpers ─────────────────────

// ListFilesInFolderRecursive returns every file in a folder tree.
// Used by the share creation flow to enumerate files for FCK backfill.
func (s *DriveStore) ListFilesInFolderRecursive(
	ctx context.Context,
	ownerUserID, tenantID, rootFolderID uuid.UUID,
) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`WITH RECURSIVE folder_tree AS (
			SELECT folder_id FROM drive_folders
			WHERE folder_id = $1 AND user_id = $2 AND tenant_id = $3
			UNION ALL
			SELECT f.folder_id FROM drive_folders f
			INNER JOIN folder_tree t ON f.parent_id = t.folder_id
			WHERE f.user_id = $2 AND f.tenant_id = $3
		)
		SELECT `+driveFileColumns+`
		FROM drive_files
		WHERE folder_id IN (SELECT folder_id FROM folder_tree)
		  AND user_id = $2 AND tenant_id = $3
		  AND trashed = false`,
		rootFolderID, ownerUserID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list files in folder recursive: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recursive file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// ListSubfoldersRecursive returns every sub-folder under a root folder.
func (s *DriveStore) ListSubfoldersRecursive(
	ctx context.Context,
	ownerUserID, tenantID, rootFolderID uuid.UUID,
) ([]*DriveFolder, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`WITH RECURSIVE folder_tree AS (
			SELECT `+driveFolderColumns+`
			FROM drive_folders
			WHERE parent_id = $1 AND user_id = $2 AND tenant_id = $3
			UNION ALL
			SELECT f.folder_id, f.user_id, f.tenant_id, f.parent_id,
			       f.current_epoch, f.created_at, f.updated_at
			FROM drive_folders f
			INNER JOIN folder_tree t ON f.parent_id = t.folder_id
			WHERE f.user_id = $2 AND f.tenant_id = $3
		)
		SELECT `+driveFolderColumns+`
		FROM folder_tree`,
		rootFolderID, ownerUserID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list subfolders recursive: %w", err)
	}
	defer rows.Close()

	var folders []*DriveFolder
	for rows.Next() {
		f, err := scanDriveFolder(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recursive folder: %w", err)
		}
		folders = append(folders, f)
	}
	return folders, nil
}

// BackfillFCKFileWraps persists fck_wrapped_message_key on file rows
// for files that don't already have one. Used by the folder link share
// creation flow to ensure all files in the tree are decryptable via FCK.
func (s *DriveStore) BackfillFCKFileWraps(ctx context.Context, ownerUserID, tenantID uuid.UUID, wraps []FCKFileWrapInput) error {
	if len(wraps) == 0 {
		return nil
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin backfill tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for _, fw := range wraps {
		_, err := tx.Exec(ctx,
			`UPDATE drive_files
			    SET fck_wrapped_message_key = $1, updated_at = now()
			  WHERE file_id = $2 AND user_id = $3 AND tenant_id = $4
			    AND fck_wrapped_message_key IS NULL`,
			fw.FCKWrappedMessageKey, fw.FileID, ownerUserID, tenantID,
		)
		if err != nil {
			return fmt.Errorf("backfill file wrap %s: %w", fw.FileID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit backfill tx: %w", err)
	}
	return nil
}

// GetFolderByID retrieves a folder by ID without user scoping.
// Used by public folder link share endpoints where ownership is verified via the share record.
func (s *DriveStore) GetFolderByID(ctx context.Context, folderID uuid.UUID) (*DriveFolder, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+driveFolderColumns+`
		 FROM drive_folders
		 WHERE folder_id = $1`,
		folderID,
	)
	if err != nil {
		return nil, fmt.Errorf("get folder by id: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("folder not found")
	}
	return scanDriveFolder(rows)
}

// ListFilesInFolderByID returns all non-trashed files in a folder tree (recursive)
// without user scoping. Used by public folder link share endpoints.
func (s *DriveStore) ListFilesInFolderByID(ctx context.Context, rootFolderID uuid.UUID) ([]*DriveFile, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`WITH RECURSIVE folder_tree AS (
			SELECT folder_id FROM drive_folders
			WHERE folder_id = $1
			UNION ALL
			SELECT f.folder_id FROM drive_folders f
			INNER JOIN folder_tree t ON f.parent_id = t.folder_id
		)
		SELECT `+driveFileColumns+`
		FROM drive_files
		WHERE folder_id IN (SELECT folder_id FROM folder_tree)
		  AND trashed = false`,
		rootFolderID,
	)
	if err != nil {
		return nil, fmt.Errorf("list files in folder by id: %w", err)
	}
	defer rows.Close()

	var files []*DriveFile
	for rows.Next() {
		f, err := scanDriveFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		files = append(files, f)
	}
	return files, nil
}

// ListSubfoldersByID returns all subfolders under a root folder (recursive)
// without user scoping. Used by public folder link share endpoints.
func (s *DriveStore) ListSubfoldersByID(ctx context.Context, rootFolderID uuid.UUID) ([]*DriveFolder, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`WITH RECURSIVE folder_tree AS (
			SELECT `+driveFolderColumns+`
			FROM drive_folders
			WHERE parent_id = $1
			UNION ALL
			SELECT f.folder_id, f.user_id, f.tenant_id, f.parent_id,
			       f.current_epoch, f.created_at, f.updated_at
			FROM drive_folders f
			INNER JOIN folder_tree t ON f.parent_id = t.folder_id
		)
		SELECT `+driveFolderColumns+`
		FROM folder_tree`,
		rootFolderID,
	)
	if err != nil {
		return nil, fmt.Errorf("list subfolders by id: %w", err)
	}
	defer rows.Close()

	var folders []*DriveFolder
	for rows.Next() {
		f, err := scanDriveFolder(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subfolder: %w", err)
		}
		folders = append(folders, f)
	}
	return folders, nil
}

// GetEpochNameForFolder returns the encrypted name for a folder at the
// given epoch. Used by public folder link share endpoints.
func (s *DriveStore) GetEpochNameForFolder(ctx context.Context, folderID uuid.UUID, epoch int) ([]byte, error) {
	var encName []byte
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT encrypted_name FROM drive_folder_epoch_names
		 WHERE folder_id = $1 AND epoch = $2`,
		folderID, epoch,
	).Scan(&encName)
	if err != nil {
		return nil, fmt.Errorf("get epoch name: %w", err)
	}
	return encName, nil
}

// ListFolderSharesForRecipient returns all folders shared with a given
// recipient user (top-level "shared with me" folder view). Each entry
// includes the folder metadata, the owner's address, and the recipient's
// current-epoch FCK wrap so the client can decrypt the folder name.
func (s *DriveStore) ListFolderSharesForRecipient(
	ctx context.Context,
	recipientUserID, tenantID uuid.UUID,
) ([]*SharedFolderEntry, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT df.folder_id, df.user_id, df.tenant_id, df.parent_id,
		        df.current_epoch, df.created_at, df.updated_at,
		        COALESCE(u.address, '') AS owner_address,
		        fs.can_edit, fs.joined_epoch, fs.past_epoch_access,
		        en.encrypted_name,
		        ek.wrapped_fck, ek.wrapped_fck_eph_pubkey
		   FROM drive_folder_shares fs
		   JOIN drive_folders df ON df.folder_id = fs.folder_id
		   LEFT JOIN users u ON u.user_id = df.user_id
		   LEFT JOIN drive_folder_epoch_names en
		     ON en.folder_id = df.folder_id AND en.epoch = df.current_epoch
		   LEFT JOIN drive_folder_epoch_keys ek
		     ON ek.folder_id = df.folder_id AND ek.epoch = df.current_epoch
		        AND ek.recipient_user_id = $1
		  WHERE fs.recipient_user_id = $1 AND fs.tenant_id = $2
		    AND (fs.expires_at IS NULL OR fs.expires_at > now())
		  ORDER BY fs.created_at DESC`,
		recipientUserID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list folder shares for recipient: %w", err)
	}
	defer rows.Close()

	var out []*SharedFolderEntry
	for rows.Next() {
		f := &DriveFolder{}
		var ownerAddr string
		var canEdit, pastEpochAccess bool
		var joinedEpoch int
		var encName, wrappedFCK, wrappedFCKEph []byte
		if err := rows.Scan(
			&f.FolderID, &f.UserID, &f.TenantID, &f.ParentID,
			&f.CurrentEpoch, &f.CreatedAt, &f.UpdatedAt,
			&ownerAddr, &canEdit, &joinedEpoch, &pastEpochAccess,
			&encName, &wrappedFCK, &wrappedFCKEph,
		); err != nil {
			return nil, fmt.Errorf("scan shared folder entry: %w", err)
		}
		out = append(out, &SharedFolderEntry{
			DriveFolder:         f,
			OwnerAddress:        ownerAddr,
			CanEdit:             canEdit,
			JoinedEpoch:         joinedEpoch,
			PastEpochAccess:     pastEpochAccess,
			EncryptedName:       encName,
			WrappedFCK:          wrappedFCK,
			WrappedFCKEphPubkey: wrappedFCKEph,
		})
	}
	return out, nil
}

// ListSharedIDs returns the distinct file_ids and folder_ids that have
// active shares owned by the given user. This allows the frontend to
// show a share indicator on the owner's own files/folders without
// changing the existing list queries.
func (s *DriveStore) ListSharedIDs(ctx context.Context, userID, tenantID uuid.UUID) (fileIDs []string, folderIDs []string, err error) {
	// File-level shares (drive_shares table).
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT DISTINCT file_id FROM drive_shares
		 WHERE user_id = $1 AND tenant_id = $2 AND file_id IS NOT NULL`,
		userID, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("list shared file ids: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fid uuid.UUID
		if err := rows.Scan(&fid); err != nil {
			return nil, nil, fmt.Errorf("scan shared file id: %w", err)
		}
		fileIDs = append(fileIDs, fid.String())
	}

	// Folder-level shares (drive_shares with folder_id set, plus
	// drive_folder_shares which is the FCK-based share membership table).
	rows2, err := s.DB.Pool.Query(ctx,
		`SELECT DISTINCT folder_id FROM (
			SELECT folder_id FROM drive_shares
			WHERE user_id = $1 AND tenant_id = $2 AND folder_id IS NOT NULL
			UNION
			SELECT folder_id FROM drive_folder_shares
			WHERE owner_user_id = $1 AND tenant_id = $2
		) sub`,
		userID, tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("list shared folder ids: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var fid uuid.UUID
		if err := rows2.Scan(&fid); err != nil {
			return nil, nil, fmt.Errorf("scan shared folder id: %w", err)
		}
		folderIDs = append(folderIDs, fid.String())
	}

	return fileIDs, folderIDs, nil
}
