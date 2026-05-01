package storage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	bmcrypto "github.com/bmailag/bmail/internal/crypto"
)

// MailStore wraps DB and provides message-related database operations.
type MailStore struct {
	DB *DB
}

// NewMailStore returns a new MailStore backed by the given DB.
func NewMailStore(db *DB) *MailStore {
	return &MailStore{DB: db}
}

// InsertMessage inserts a new message into the messages table.
//
// Phase B3: per-field encrypted address columns are gone (migration
// 070). Addressing rides on the single encrypted_headers blob, which
// shares the body's message key, plus a blind index for SGX-side
// sender lookups.
func (s *MailStore) InsertMessage(ctx context.Context, msg *Message) error {
	encType := msg.EncryptionType
	if encType == "" {
		encType = "bmail"
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO messages (message_id, user_id, tenant_id, folder_id, blob_ref,
			encrypted_subject, encrypted_message_key, ephemeral_pubkey,
			received_at, size_bytes, has_attachments, is_read, key_epoch,
			enclave_receipt, in_reply_to, "references", thread_id, encryption_type, subject, rfc_message_id, raw_blob_ref, raw_blob_format, encrypted_raw_meta,
			sender_blind_index, encrypted_headers, is_starred)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		msg.MessageID, msg.UserID, msg.TenantID, msg.FolderID, msg.BlobRef,
		msg.EncryptedSubject, msg.EncryptedMessageKey, msg.EphemeralPubkey,
		msg.ReceivedAt, msg.SizeBytes, msg.HasAttachments, msg.IsRead, msg.KeyEpoch,
		msg.EnclaveReceipt, msg.InReplyTo, msg.References, msg.ThreadID, encType, msg.Subject, msg.RFCMessageID, msg.RawBlobRef, msg.RawBlobFormat, msg.EncryptedRawMeta,
		msg.SenderBlindIndex, msg.EncryptedHeaders, msg.IsStarred,
	)
	if err != nil {
		return fmt.Errorf("insert message: %w", err)
	}
	return nil
}

// StringPtr returns a pointer to a string, or nil if empty.
func StringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// DerefString returns the dereferenced string or empty string if nil.
func DerefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// messageColumns is the common column list for SELECT queries.
//
// Phase B3: per-field bare envelope columns are dropped by migration
// 070. Addressing comes from encrypted_headers + sender_blind_index.
const messageColumns = `message_id, user_id, tenant_id, folder_id, blob_ref,
	encrypted_subject, encrypted_message_key, ephemeral_pubkey,
	received_at, size_bytes, has_attachments, is_read, key_epoch,
	enclave_receipt, in_reply_to, "references", thread_id, COALESCE(encryption_type, 'bmail'), is_starred, subject, rfc_message_id, raw_blob_ref, COALESCE(raw_blob_format, 'XChaCha20-Poly1305'), encrypted_raw_meta,
	COALESCE(sender_blind_index, ''),
	COALESCE(encrypted_headers, ''::bytea)`

// qualifiedMessageColumns returns the column list with a table alias prefix.
func qualifiedMessageColumns(alias string) string {
	return fmt.Sprintf(`%[1]s.message_id, %[1]s.user_id, %[1]s.tenant_id, %[1]s.folder_id, %[1]s.blob_ref,
	%[1]s.encrypted_subject, %[1]s.encrypted_message_key, %[1]s.ephemeral_pubkey,
	%[1]s.received_at, %[1]s.size_bytes, %[1]s.has_attachments, %[1]s.is_read, %[1]s.key_epoch,
	%[1]s.enclave_receipt, %[1]s.in_reply_to, %[1]s."references", %[1]s.thread_id, COALESCE(%[1]s.encryption_type, 'bmail'), %[1]s.is_starred, %[1]s.subject, %[1]s.rfc_message_id, %[1]s.raw_blob_ref, COALESCE(%[1]s.raw_blob_format, 'XChaCha20-Poly1305'), %[1]s.encrypted_raw_meta,
	COALESCE(%[1]s.sender_blind_index, ''),
	COALESCE(%[1]s.encrypted_headers, ''::bytea)`, alias)
}

// scannable is satisfied by both pgx.Row and pgx.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func scanMessage(row scannable) (*Message, error) {
	m := &Message{}
	err := row.Scan(
		&m.MessageID, &m.UserID, &m.TenantID, &m.FolderID, &m.BlobRef,
		&m.EncryptedSubject, &m.EncryptedMessageKey, &m.EphemeralPubkey,
		&m.ReceivedAt, &m.SizeBytes, &m.HasAttachments, &m.IsRead, &m.KeyEpoch,
		&m.EnclaveReceipt, &m.InReplyTo, &m.References, &m.ThreadID, &m.EncryptionType, &m.IsStarred, &m.Subject,
		&m.RFCMessageID, &m.RawBlobRef, &m.RawBlobFormat, &m.EncryptedRawMeta,
		&m.SenderBlindIndex, &m.EncryptedHeaders,
	)
	return m, err
}

// ListMessages returns messages for a user in a folder scoped to a tenant, ordered by received_at DESC.
func (s *MailStore) ListMessages(ctx context.Context, userID, tenantID, folderID uuid.UUID, limit, offset int) ([]*Message, error) {
	rows, err := s.DB.Pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM messages
		 WHERE user_id = $1 AND folder_id = $2 AND tenant_id = $3
		 ORDER BY received_at DESC
		 LIMIT $4 OFFSET $5`, messageColumns),
		userID, folderID, tenantID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return msgs, nil
}

// ListMessagesByLabel returns messages that have a specific label, scoped to a user and tenant.
func (s *MailStore) ListMessagesByLabel(ctx context.Context, userID, tenantID, labelID uuid.UUID, limit, offset int) ([]*Message, error) {
	rows, err := s.DB.Pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM messages m
		 INNER JOIN message_labels ml ON ml.message_id = m.message_id
		 WHERE m.user_id = $1 AND m.tenant_id = $2 AND ml.label_id = $3
		 ORDER BY m.received_at DESC
		 LIMIT $4 OFFSET $5`, qualifiedMessageColumns("m")),
		userID, tenantID, labelID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list messages by label: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return msgs, nil
}

// GetMessage retrieves a single message by ID for the given user and tenant.
func (s *MailStore) GetMessage(ctx context.Context, messageID, userID, tenantID uuid.UUID) (*Message, error) {
	row := s.DB.Pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM messages WHERE message_id = $1 AND user_id = $2 AND tenant_id = $3`, messageColumns),
		messageID, userID, tenantID,
	)
	m, err := scanMessage(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("message not found: %s", messageID)
	}
	if err != nil {
		return nil, fmt.Errorf("get message: %w", err)
	}
	return m, nil
}

// GetMessagesByThread returns all messages in a thread for the given user and tenant.
func (s *MailStore) GetMessagesByThread(ctx context.Context, userID, tenantID uuid.UUID, threadID uuid.UUID) ([]*Message, error) {
	rows, err := s.DB.Pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM messages
		 WHERE user_id = $1 AND thread_id = $2 AND tenant_id = $3
		 ORDER BY received_at ASC`, messageColumns),
		userID, threadID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get thread messages: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan thread message: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate thread messages: %w", err)
	}
	return msgs, nil
}

// GetMessageByRFCMessageID looks up a message by its RFC 5322 Message-ID header,
// scoped to a tenant. Used to resolve In-Reply-To headers for threading.
func (s *MailStore) GetMessageByRFCMessageID(ctx context.Context, tenantID uuid.UUID, rfcMessageID string) (*Message, error) {
	row := s.DB.Pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM messages WHERE rfc_message_id = $1 AND tenant_id = $2 LIMIT 1`, messageColumns),
		rfcMessageID, tenantID,
	)
	m, err := scanMessage(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get message by rfc_message_id: %w", err)
	}
	return m, nil
}

// UpdateThreadID sets the thread_id on an existing message. Used to backfill
// thread_id on the original message when a reply arrives.
func (s *MailStore) UpdateThreadID(ctx context.Context, messageID, tenantID uuid.UUID, threadID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET thread_id = $1 WHERE message_id = $2 AND tenant_id = $3`,
		threadID, messageID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update thread_id: %w", err)
	}
	return nil
}

// UpdateThreadIDByRFCMessageID backfills thread_id on every copy of a logical
// message within a tenant (sender's sent copy and every recipient's copy all
// share the same RFC Message-ID). Only updates rows that don't already have
// a thread_id so an existing thread isn't clobbered.
func (s *MailStore) UpdateThreadIDByRFCMessageID(ctx context.Context, rfcMessageID string, tenantID uuid.UUID, threadID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET thread_id = $1
		 WHERE rfc_message_id = $2 AND tenant_id = $3 AND thread_id IS NULL`,
		threadID, rfcMessageID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update thread_id by rfc_message_id: %w", err)
	}
	return nil
}

// MoveMessagesByTenant moves messages to a target folder for the given user and tenant.
func (s *MailStore) MoveMessagesByTenant(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID, targetFolderID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET folder_id = $4
		 WHERE user_id = $1 AND message_id = ANY($2) AND tenant_id = $3`,
		userID, messageIDs, tenantID, targetFolderID,
	)
	if err != nil {
		return fmt.Errorf("move messages: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no messages found to move")
	}
	return nil
}

// PruneOldestMessages deletes up to `batchSize` oldest messages for
// the user, decrements users.storage_used_bytes by the freed amount
// in the same transaction, and returns counters for logging. Used by
// the lifecycle pruning worker to walk an over-cap free-tier account
// back under its 100 MB limit one batch at a time. Returns (0, 0, nil)
// when there's nothing to prune.
func (s *MailStore) PruneOldestMessages(ctx context.Context, userID, tenantID uuid.UUID, batchSize int) (bytesFreed int64, deleted int, err error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin prune tx: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT message_id, COALESCE(size_bytes, 0)
		 FROM messages
		 WHERE user_id = $1 AND tenant_id = $2
		 ORDER BY received_at ASC NULLS FIRST
		 LIMIT $3`,
		userID, tenantID, batchSize,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("list oldest messages: %w", err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var sz int64
		if scanErr := rows.Scan(&id, &sz); scanErr != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("scan oldest message: %w", scanErr)
		}
		ids = append(ids, id)
		bytesFreed += sz
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate oldest messages: %w", err)
	}
	if len(ids) == 0 {
		return 0, 0, tx.Commit(ctx)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM messages WHERE user_id = $1 AND tenant_id = $2 AND message_id = ANY($3)`,
		userID, tenantID, ids,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("delete oldest messages: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET storage_used_bytes = GREATEST(0, storage_used_bytes - $2)
		 WHERE user_id = $1 AND tenant_id = $3`,
		userID, bytesFreed, tenantID,
	); err != nil {
		return 0, 0, fmt.Errorf("decrement storage: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit prune: %w", err)
	}
	return bytesFreed, int(tag.RowsAffected()), nil
}


// DeleteMessagesByTenant deletes messages for the given user and tenant.
func (s *MailStore) DeleteMessagesByTenant(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM messages WHERE user_id = $1 AND message_id = ANY($2) AND tenant_id = $3`,
		userID, messageIDs, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete messages: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no messages found to delete")
	}
	return nil
}

// MarkReadByTenant sets the is_read flag on messages for the given user and tenant.
func (s *MailStore) MarkReadByTenant(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID, isRead bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET is_read = $4
		 WHERE user_id = $1 AND message_id = ANY($2) AND tenant_id = $3`,
		userID, messageIDs, tenantID, isRead,
	)
	if err != nil {
		return fmt.Errorf("mark read: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no messages found to update")
	}
	return nil
}


// UpdateDraftByTenant updates an existing draft message's encrypted
// content. Phase B3: the encrypted_headers blob is now the addressing
// source of truth — pass an updated blob to refresh the saved
// recipients (or pass nil to leave the existing blob alone).
func (s *MailStore) UpdateDraftByTenant(ctx context.Context, messageID, userID, tenantID uuid.UUID, blobRef string, encSubject, encMsgKey, ephPub, encHeaders []byte, sizeBytes int64) error {
	if encHeaders != nil {
		tag, err := s.DB.Pool.Exec(ctx,
			`UPDATE messages SET blob_ref = $3, encrypted_subject = $4, encrypted_message_key = $5,
				ephemeral_pubkey = $6, size_bytes = $7, encrypted_headers = $9
			 WHERE message_id = $1 AND user_id = $2 AND tenant_id = $8`,
			messageID, userID, blobRef, encSubject, encMsgKey, ephPub, sizeBytes, tenantID, encHeaders,
		)
		if err != nil {
			return fmt.Errorf("update draft: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("draft not found")
		}
		return nil
	}
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET blob_ref = $3, encrypted_subject = $4, encrypted_message_key = $5,
			ephemeral_pubkey = $6, size_bytes = $7
		 WHERE message_id = $1 AND user_id = $2 AND tenant_id = $8`,
		messageID, userID, blobRef, encSubject, encMsgKey, ephPub, sizeBytes, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update draft: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("draft not found")
	}
	return nil
}

// CountUnread returns the number of unread messages in a folder for the given user and tenant.
func (s *MailStore) CountUnread(ctx context.Context, userID, tenantID, folderID uuid.UUID) (int, error) {
	var count int
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE user_id = $1 AND folder_id = $2 AND tenant_id = $3 AND is_read = false`,
		userID, folderID, tenantID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count unread: %w", err)
	}
	return count, nil
}

// BackfillMessageHeaders walks rows that have legacy plaintext
// addresses still in the schema (sender_address / recipient_address /
// cc_addresses / bcc_addresses) but no encrypted_headers blob yet,
// builds a small RFC-5322-shaped headers JSON, encrypts it to the
// row owner's bmail public key (with its OWN envelope), and writes
// it into encrypted_headers. Idempotent — rows that already have a
// blob are skipped, and rows whose legacy columns have already been
// dropped by migration 068 are quietly no-op'd.
//
// Pre-B1 messages have legacy plaintext but no bare envelopes — those
// are recoverable here. B1+ messages whose legacy plaintext was
// nuked by 068 without a prior backfill are NOT recoverable from the
// server side (the bare envelopes are encrypted to the user's
// pubkey, which the server can't open).
//
// MUST be run before migration 070 drops the bare envelope columns.
// The 070 migration's guard refuses to drop them if any row still
// has bare envelopes but no encrypted_headers.
func (s *MailStore) BackfillMessageHeaders(ctx context.Context, authStore *AuthStore) (int, error) {
	// Detect which columns are present so the SELECT compiles cleanly
	// on databases at any phase of the migration timeline. On a fresh
	// catch-up (prod at version 55) neither legacy plaintext nor
	// encrypted_headers may exist yet — bail out as no-op rather than
	// erroring on missing columns. On a fully-migrated box, legacy
	// plaintext is gone and there's nothing for the server to recover.
	var hasLegacyPlaintext, hasEncryptedHeaders bool
	if err := s.DB.Pool.QueryRow(ctx,
		`SELECT
			EXISTS (SELECT 1 FROM information_schema.columns
			        WHERE table_schema = 'public' AND table_name = 'messages' AND column_name = 'sender_address'),
			EXISTS (SELECT 1 FROM information_schema.columns
			        WHERE table_schema = 'public' AND table_name = 'messages' AND column_name = 'encrypted_headers')`,
	).Scan(&hasLegacyPlaintext, &hasEncryptedHeaders); err != nil {
		return 0, fmt.Errorf("backfill headers: probe schema: %w", err)
	}
	slog.Info("backfill probe", "has_legacy_plaintext", hasLegacyPlaintext, "has_encrypted_headers", hasEncryptedHeaders)
	if !hasLegacyPlaintext || !hasEncryptedHeaders {
		// Either nothing to recover from, or the destination column
		// hasn't been added yet (run migrate -target=68 first). Both
		// are valid no-op states.
		return 0, nil
	}

	rows, err := s.DB.Pool.Query(ctx,
		`SELECT message_id, user_id,
		        COALESCE(sender_address, ''),
		        COALESCE(recipient_address, ''),
		        COALESCE(cc_addresses, ''),
		        COALESCE(bcc_addresses, '')
		 FROM messages
		 WHERE encrypted_headers IS NULL
		   AND (sender_address IS NOT NULL OR recipient_address IS NOT NULL OR cc_addresses IS NOT NULL OR bcc_addresses IS NOT NULL)
		 LIMIT 50000`,
	)
	if err != nil {
		return 0, fmt.Errorf("backfill headers: list pending: %w", err)
	}
	type pending struct {
		id        uuid.UUID
		userID    uuid.UUID
		sender    string
		recipient string
		cc        string
		bcc       string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.userID, &p.sender, &p.recipient, &p.cc, &p.bcc); err != nil {
			rows.Close()
			return 0, fmt.Errorf("backfill headers: scan: %w", err)
		}
		todo = append(todo, p)
	}
	rows.Close()
	slog.Info("backfill select", "todo_rows", len(todo))
	if len(todo) == 0 {
		return 0, nil
	}

	// Use a narrow SELECT for the user's encryption pubkey instead of
	// authStore.GetUserByID. The full GetUserByID query references
	// columns added by migrations 069-091 (has_fakeid, public_key_kem,
	// account_type, …). On a catch-up deploy this backfill runs
	// between migrate -target=68 and the rest of migrate up, so those
	// columns don't exist yet and GetUserByID errors on every row.
	pubKeyCache := make(map[uuid.UUID][]byte)
	getPubKey := func(uid uuid.UUID) ([]byte, error) {
		if k, ok := pubKeyCache[uid]; ok {
			return k, nil
		}
		var pub []byte
		err := s.DB.Pool.QueryRow(ctx,
			`SELECT public_key_encryption FROM users WHERE user_id = $1`,
			uid,
		).Scan(&pub)
		if err != nil {
			return nil, err
		}
		pubKeyCache[uid] = pub
		return pub, nil
	}

	var skipNoPubKey, skipBadPubKey, skipBuildJSON, skipEncrypt, skipWrap, skipUpdate int
	count := 0
	for _, p := range todo {
		pubKey, err := getPubKey(p.userID)
		if err != nil {
			skipNoPubKey++
			continue
		}
		if len(pubKey) != 32 {
			skipBadPubKey++
			continue
		}
		toList := splitAddressLine(p.recipient)
		ccList := splitAddressLine(p.cc)
		bccList := splitAddressLine(p.bcc)
		headersJSON, err := BuildSimpleHeadersJSON(p.sender, toList, ccList, bccList, "", "", "", "")
		if err != nil {
			skipBuildJSON++
			continue
		}
		enc, err := EncryptStandaloneHeaders(pubKey, headersJSON)
		if err != nil {
			skipEncrypt++
			continue
		}

		// Pack the standalone envelope into a JSON wrapper inside
		// encrypted_headers so the client can decrypt it without
		// touching the row's body envelope (the body is encrypted
		// with a different message key — the user's, when they sent
		// the message originally — and we can't unwrap it server
		// side). The client picks the wrapper format apart with
		// JSON.parse before falling back to the row's eph + key.
		wrapped, err := wrapStandaloneHeaders(enc)
		if err != nil {
			skipWrap++
			continue
		}

		var blind any
		if p.sender != "" {
			blind = ComputeAddressBlindIndex(BlindScopeMessageSender, p.userID, p.sender)
		}
		_, err = s.DB.Pool.Exec(ctx,
			`UPDATE messages SET encrypted_headers = $2, sender_blind_index = COALESCE(sender_blind_index, $3) WHERE message_id = $1`,
			p.id, wrapped, blind,
		)
		if err != nil {
			skipUpdate++
			continue
		}
		count++
	}
	if skipNoPubKey+skipBadPubKey+skipBuildJSON+skipEncrypt+skipWrap+skipUpdate > 0 {
		slog.Info("backfill skips",
			"no_pubkey", skipNoPubKey,
			"bad_pubkey_len", skipBadPubKey,
			"build_json", skipBuildJSON,
			"encrypt", skipEncrypt,
			"wrap", skipWrap,
			"update", skipUpdate,
		)
	}
	return count, nil
}

// splitAddressLine breaks a comma-separated header value back into
// individual addresses. Empty input → empty slice (not nil) so
// BuildSimpleHeadersJSON omits the field cleanly.
func splitAddressLine(value string) []string {
	if value == "" {
		return nil
	}
	out := []string{}
	for _, p := range bytesSplitComma(value) {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func bytesSplitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimSpace(s[start:]))
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// wrapStandaloneHeaders serializes a standalone envelope into a JSON
// wrapper the client can recognise: {ephemeral_pubkey, encrypted_message_key,
// encrypted_headers}. The client tries the row's body envelope first;
// if that fails it falls through to JSON.parse on the blob and uses
// the embedded envelope to decrypt. Lets backfilled rows display
// without sharing keys with the body.
func wrapStandaloneHeaders(enc *bmcrypto.EncryptedMessage) ([]byte, error) {
	// Avoid pulling encoding/json into this file's import surface by
	// hand-rolling the small wrapper. (The whole shape is three
	// base64 strings — fmt.Sprintf is plenty.)
	const tmpl = `{"ephemeral_pubkey":%q,"encrypted_message_key":%q,"encrypted_headers":%q}`
	return []byte(fmt.Sprintf(tmpl,
		base64Encode(enc.EphemeralPubkey),
		base64Encode(enc.EncryptedMessageKey),
		base64Encode(enc.EncryptedHeaders),
	)), nil
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// MarkStarredByTenant sets the is_starred flag on messages for the given user and tenant.
func (s *MailStore) MarkStarredByTenant(ctx context.Context, userID, tenantID uuid.UUID, messageIDs []uuid.UUID, starred bool) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE messages SET is_starred = $4
		 WHERE user_id = $1 AND message_id = ANY($2) AND tenant_id = $3`,
		userID, messageIDs, tenantID, starred,
	)
	if err != nil {
		return fmt.Errorf("mark starred: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("no messages found to update")
	}
	return nil
}
