package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Contact represents a row in the contacts table.
//
// Address is encrypted at rest. The legacy plaintext `address` column
// stays NULLABLE on disk during the transition (will be dropped in a
// follow-up migration), but the in-memory struct field is now always
// the cleartext value when known by the caller — server code that
// needs the cleartext (e.g. to display in an API response after
// decrypt) sets it; server code that only does lookups uses
// AddressBlindIndex instead.
type Contact struct {
	ID                 uuid.UUID  `db:"id"`
	UserID             uuid.UUID  `db:"user_id"`
	TenantID           uuid.UUID  `db:"tenant_id"`
	Address            string     `db:"address"` // legacy plaintext (transitional)
	AddressEncrypted   []byte     `db:"address_encrypted"`
	AddressEphemeral   []byte     `db:"address_ephemeral"`
	AddressEncKey      []byte     `db:"address_enc_key"`
	AddressBlindIndex  string     `db:"address_blind_index"`
	NameEncrypted      []byte     `db:"name_encrypted"`
	PublicKeyEnc       []byte     `db:"public_key_enc"`
	LastContacted      *time.Time `db:"last_contacted"`
	Trusted            bool       `db:"trusted"`
	CreatedAt          time.Time  `db:"created_at"`
	PGPPublicKey       string     `db:"pgp_public_key"`
	SMIMECertificate   []byte     `db:"smime_certificate"`
	EncryptedPhone     []byte     `db:"encrypted_phone"`
	EncryptedNotes     []byte     `db:"encrypted_notes"`
	EncryptedOrg       []byte     `db:"encrypted_org"`
	EncryptedBirthday  []byte     `db:"encrypted_birthday"`
}

// ContactsStore wraps DB and provides contacts-related database operations.
type ContactsStore struct {
	DB *DB
}

// NewContactsStore returns a new ContactsStore backed by the given DB.
func NewContactsStore(db *DB) *ContactsStore {
	return &ContactsStore{DB: db}
}

// CreateContact inserts a new contact.
//
// The caller MUST have populated the encrypted address fields and the
// blind index BEFORE calling. The legacy plaintext `address` column is
// no longer written (NULL on insert) — it stays in the schema only for
// the in-progress backfill of pre-existing rows.
func (s *ContactsStore) CreateContact(ctx context.Context, c *Contact) error {
	if c.AddressBlindIndex == "" || len(c.AddressEncrypted) == 0 {
		return fmt.Errorf("create contact: address must be encrypted before insert")
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO contacts (
			id, user_id, tenant_id,
			address_encrypted, address_ephemeral, address_enc_key, address_blind_index,
			name_encrypted, public_key_enc, last_contacted, trusted, created_at
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (user_id, address_blind_index) WHERE address_blind_index IS NOT NULL DO NOTHING`,
		c.ID, c.UserID, c.TenantID,
		c.AddressEncrypted, c.AddressEphemeral, c.AddressEncKey, c.AddressBlindIndex,
		c.NameEncrypted, c.PublicKeyEnc, c.LastContacted, c.Trusted, c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create contact: %w", err)
	}
	return nil
}

// contactSelectColumns is the shared column list for contact queries.
//
// Pulls both the legacy plaintext `address` (still populated for old rows
// pending the follow-up drop migration) and the new encrypted columns.
// COALESCE on the legacy column so callers can default-display it when
// the encrypted version hasn't been backfilled yet.
const contactSelectColumns = `id, user_id, tenant_id, COALESCE(address, ''),
	COALESCE(address_encrypted, ''::bytea),
	COALESCE(address_ephemeral, ''::bytea),
	COALESCE(address_enc_key, ''::bytea),
	COALESCE(address_blind_index, ''),
	name_encrypted, public_key_enc, last_contacted, trusted, created_at,
	COALESCE(pgp_public_key, ''), smime_certificate,
	encrypted_phone, encrypted_notes, encrypted_org, encrypted_birthday`

// scanContact scans a single contact row using the shared column list.
func scanContact(rows pgx.Rows) (*Contact, error) {
	c := &Contact{}
	if err := rows.Scan(
		&c.ID, &c.UserID, &c.TenantID, &c.Address,
		&c.AddressEncrypted, &c.AddressEphemeral, &c.AddressEncKey, &c.AddressBlindIndex,
		&c.NameEncrypted,
		&c.PublicKeyEnc, &c.LastContacted, &c.Trusted, &c.CreatedAt,
		&c.PGPPublicKey, &c.SMIMECertificate,
		&c.EncryptedPhone, &c.EncryptedNotes, &c.EncryptedOrg, &c.EncryptedBirthday,
	); err != nil {
		return nil, err
	}
	return c, nil
}

// ListContacts returns all contacts for a user within a tenant.
//
// Ordered by created_at (newest first) since the address column is now
// encrypted and can't be sorted alphabetically server-side. Clients
// that want alphabetical order sort locally after decryption.
func (s *ContactsStore) ListContacts(ctx context.Context, userID, tenantID uuid.UUID) ([]*Contact, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+contactSelectColumns+`
		 FROM contacts WHERE user_id = $1 AND tenant_id = $2 ORDER BY created_at DESC`, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan contact: %w", err)
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// ContactUpdate holds the mutable fields for updating a contact.
type ContactUpdate struct {
	NameEncrypted    []byte
	Trusted          *bool
	EncryptedPhone   []byte
	EncryptedNotes   []byte
	EncryptedOrg     []byte
	EncryptedBirthday []byte
	// ClearPhone / ClearNotes / ClearOrg / ClearBirthday: when true, the
	// field is explicitly set to NULL (the caller passed an empty string
	// to clear the value, rather than omitting the field entirely).
	ClearPhone    bool
	ClearNotes    bool
	ClearOrg      bool
	ClearBirthday bool
}

// UpdateContact updates a contact's mutable fields.
func (s *ContactsStore) UpdateContact(ctx context.Context, userID, tenantID, contactID uuid.UUID, upd ContactUpdate) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE contacts
		 SET name_encrypted    = COALESCE($3, name_encrypted),
		     trusted           = COALESCE($4, trusted),
		     encrypted_phone   = CASE WHEN $6 THEN NULL ELSE COALESCE($7, encrypted_phone) END,
		     encrypted_notes   = CASE WHEN $8 THEN NULL ELSE COALESCE($9, encrypted_notes) END,
		     encrypted_org     = CASE WHEN $10 THEN NULL ELSE COALESCE($11, encrypted_org) END,
		     encrypted_birthday = CASE WHEN $12 THEN NULL ELSE COALESCE($13, encrypted_birthday) END
		 WHERE id = $1 AND user_id = $2 AND tenant_id = $5`,
		contactID, userID, upd.NameEncrypted, upd.Trusted, tenantID,
		upd.ClearPhone, upd.EncryptedPhone,
		upd.ClearNotes, upd.EncryptedNotes,
		upd.ClearOrg, upd.EncryptedOrg,
		upd.ClearBirthday, upd.EncryptedBirthday,
	)
	if err != nil {
		return fmt.Errorf("update contact: %w", err)
	}
	return nil
}

// DeleteContact removes a contact.
func (s *ContactsStore) DeleteContact(ctx context.Context, userID, tenantID, contactID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM contacts WHERE id = $1 AND user_id = $2 AND tenant_id = $3`, contactID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete contact: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("contact not found")
	}
	return nil
}

// SearchContacts returns the most recent N contacts for a user. The
// previous server-side ILIKE prefix search is gone — addresses are
// encrypted at rest and can't be substring-matched server-side.
// Callers (compose autocomplete) decrypt the returned list and filter
// locally. The query parameter is intentionally ignored to keep the
// API call shape stable for older clients.
func (s *ContactsStore) SearchContacts(ctx context.Context, userID, tenantID uuid.UUID, _ string) ([]*Contact, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+contactSelectColumns+`
		 FROM contacts WHERE user_id = $1 AND tenant_id = $2
		 ORDER BY COALESCE(last_contacted, created_at) DESC
		 LIMIT 200`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("search contacts: %w", err)
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan contact: %w", err)
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// ContactExistsByBlindIndex checks if a contact with the given blind
// index exists. Replaces the legacy ContactExists(address string) which
// required a server-side cleartext lookup.
func (s *ContactsStore) ContactExistsByBlindIndex(ctx context.Context, userID, tenantID uuid.UUID, blindIndex string) (bool, error) {
	var id uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT id FROM contacts WHERE user_id = $1 AND tenant_id = $2 AND address_blind_index = $3`,
		userID, tenantID, blindIndex,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("contact exists: %w", err)
	}
	return true, nil
}

// ContactExists is a convenience wrapper that computes the blind index
// from the cleartext address. Use this when the caller already has the
// cleartext at hand (e.g. inbound SMTP envelope, contact creation API).
// Server-internal cleartext is acceptable here — it's not persisted.
func (s *ContactsStore) ContactExists(ctx context.Context, userID, tenantID uuid.UUID, address string) (bool, error) {
	blindIndex := ComputeAddressBlindIndex(BlindScopeContact, userID, address)
	return s.ContactExistsByBlindIndex(ctx, userID, tenantID, blindIndex)
}

// AutoAdd inserts the given sender into the user's contact book if it
// isn't already present, and bumps last_contacted on existing rows.
// Encrypts the address to userPubKey before persisting — never stores
// cleartext on disk. Errors are returned to the caller (the inbound
// pipeline currently just logs them and continues).
//
// This is a thin storage helper extracted from the old
// contacts.ContactsService.AutoAddContact so the SMTP enclave pipeline
// can call it without pulling in the contacts package's HTTP handlers.
func (s *ContactsStore) AutoAdd(ctx context.Context, userID, tenantID uuid.UUID, userPubKey, userKEMPubKey []byte, address string) error {
	if address == "" {
		return nil
	}
	blindIndex := ComputeAddressBlindIndex(BlindScopeContact, userID, address)
	exists, err := s.ContactExistsByBlindIndex(ctx, userID, tenantID, blindIndex)
	if err != nil {
		return fmt.Errorf("auto add: check existence: %w", err)
	}
	if exists {
		now := time.Now()
		if err := s.UpdateLastContactedByBlindIndex(ctx, userID, tenantID, blindIndex, &now); err != nil {
			return fmt.Errorf("auto add: bump last_contacted: %w", err)
		}
		return nil
	}
	enc, err := EncryptAddressForUserHybrid(userPubKey, userKEMPubKey, address)
	if err != nil {
		return fmt.Errorf("auto add: encrypt: %w", err)
	}
	contact := &Contact{
		ID:                uuid.New(),
		UserID:            userID,
		TenantID:          tenantID,
		AddressEncrypted:  enc.Encrypted,
		AddressEphemeral:  enc.Ephemeral,
		AddressEncKey:     enc.EncryptedKey,
		AddressBlindIndex: blindIndex,
		CreatedAt:         time.Now(),
	}
	if err := s.CreateContact(ctx, contact); err != nil {
		return fmt.Errorf("auto add: create: %w", err)
	}
	return nil
}

// UpdateContactPGPKey updates a contact's PGP public key (learned from Autocrypt).
// Looks up the contact by blind index computed from the cleartext address.
func (s *ContactsStore) UpdateContactPGPKey(ctx context.Context, userID, tenantID uuid.UUID, address, pgpKey string) error {
	blindIndex := ComputeAddressBlindIndex(BlindScopeContact, userID, address)
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE contacts SET pgp_public_key = $3
		 WHERE user_id = $1 AND tenant_id = $4 AND address_blind_index = $2`,
		userID, blindIndex, pgpKey, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update contact pgp key: %w", err)
	}
	return nil
}

// CountContacts returns the number of contacts for a user within a tenant.
func (s *ContactsStore) CountContacts(ctx context.Context, userID, tenantID uuid.UUID) (int64, error) {
	var count int64
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM contacts WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count contacts: %w", err)
	}
	return count, nil
}

// ContactGroup represents a row in the contact_groups table.
type ContactGroup struct {
	GroupID       uuid.UUID `db:"group_id"`
	TenantID      uuid.UUID `db:"tenant_id"`
	UserID        uuid.UUID `db:"user_id"`
	NameEncrypted []byte    `db:"name_encrypted"`
	CreatedAt     time.Time `db:"created_at"`
	MemberCount   int       `db:"-"`
}

// CreateGroup inserts a new contact group.
func (s *ContactsStore) CreateGroup(ctx context.Context, g *ContactGroup) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO contact_groups (group_id, tenant_id, user_id, name_encrypted, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		g.GroupID, g.TenantID, g.UserID, g.NameEncrypted, g.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create group: %w", err)
	}
	return nil
}

// ListGroups returns all contact groups for a user within a tenant, with member counts.
func (s *ContactsStore) ListGroups(ctx context.Context, userID, tenantID uuid.UUID) ([]*ContactGroup, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT g.group_id, g.tenant_id, g.user_id, g.name_encrypted, g.created_at,
		        COUNT(m.contact_id)::int AS member_count
		 FROM contact_groups g
		 LEFT JOIN contact_group_members m ON g.group_id = m.group_id
		 WHERE g.user_id = $1 AND g.tenant_id = $2
		 GROUP BY g.group_id
		 ORDER BY g.created_at`, userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []*ContactGroup
	for rows.Next() {
		g := &ContactGroup{}
		if err := rows.Scan(&g.GroupID, &g.TenantID, &g.UserID, &g.NameEncrypted, &g.CreatedAt, &g.MemberCount); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// UpdateGroup updates a contact group's name.
func (s *ContactsStore) UpdateGroup(ctx context.Context, userID, tenantID, groupID uuid.UUID, nameEncrypted []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE contact_groups SET name_encrypted = $4
		 WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3`,
		groupID, userID, tenantID, nameEncrypted,
	)
	if err != nil {
		return fmt.Errorf("update group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

// DeleteGroup deletes a contact group (members are cascade-deleted).
func (s *ContactsStore) DeleteGroup(ctx context.Context, userID, tenantID, groupID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM contact_groups WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3`,
		groupID, userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}

// AddGroupMember adds a contact to a group.
func (s *ContactsStore) AddGroupMember(ctx context.Context, userID, tenantID, groupID, contactID uuid.UUID) error {
	// Verify group belongs to user.
	var gid uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT group_id FROM contact_groups WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3`,
		groupID, userID, tenantID,
	).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("group not found")
	}
	if err != nil {
		return fmt.Errorf("verify group: %w", err)
	}

	// Verify contact belongs to same tenant before linking.
	var cid uuid.UUID
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT id FROM contacts WHERE id = $1 AND tenant_id = $2`,
		contactID, tenantID,
	).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("contact not found")
	}
	if err != nil {
		return fmt.Errorf("verify contact: %w", err)
	}

	_, err = s.DB.Pool.Exec(ctx,
		`INSERT INTO contact_group_members (group_id, contact_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`,
		groupID, contactID,
	)
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a contact from a group.
func (s *ContactsStore) RemoveGroupMember(ctx context.Context, userID, tenantID, groupID, contactID uuid.UUID) error {
	// Verify group belongs to user.
	var gid uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT group_id FROM contact_groups WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3`,
		groupID, userID, tenantID,
	).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("group not found")
	}
	if err != nil {
		return fmt.Errorf("verify group: %w", err)
	}

	// Verify contact belongs to same tenant before unlinking.
	var cid uuid.UUID
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT id FROM contacts WHERE id = $1 AND tenant_id = $2`,
		contactID, tenantID,
	).Scan(&cid)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("contact not found")
	}
	if err != nil {
		return fmt.Errorf("verify contact: %w", err)
	}

	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM contact_group_members WHERE group_id = $1 AND contact_id = $2`,
		groupID, contactID,
	)
	if err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member not found")
	}
	return nil
}

// GetGroupMembers returns the contacts in a group.
func (s *ContactsStore) GetGroupMembers(ctx context.Context, userID, tenantID, groupID uuid.UUID) ([]*Contact, error) {
	// Verify group belongs to user.
	var gid uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT group_id FROM contact_groups WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3`,
		groupID, userID, tenantID,
	).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("group not found")
	}
	if err != nil {
		return nil, fmt.Errorf("verify group: %w", err)
	}

	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+contactSelectColumns+`
		 FROM contacts c
		 JOIN contact_group_members m ON c.id = m.contact_id
		 WHERE m.group_id = $1 AND c.tenant_id = $2
		 ORDER BY c.created_at DESC`, groupID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("get group members: %w", err)
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// UpdateLastContacted updates the last_contacted timestamp. Looks up
// the contact by blind index computed from the cleartext address.
func (s *ContactsStore) UpdateLastContacted(ctx context.Context, userID, tenantID uuid.UUID, address string, t *time.Time) error {
	blindIndex := ComputeAddressBlindIndex(BlindScopeContact, userID, address)
	return s.UpdateLastContactedByBlindIndex(ctx, userID, tenantID, blindIndex, t)
}

// UpdateLastContactedByBlindIndex updates last_contacted using a
// pre-computed blind index. Use this when the caller already has the
// blind index (e.g. AutoAdd).
func (s *ContactsStore) UpdateLastContactedByBlindIndex(ctx context.Context, userID, tenantID uuid.UUID, blindIndex string, t *time.Time) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE contacts SET last_contacted = $3
		 WHERE user_id = $1 AND tenant_id = $4 AND address_blind_index = $2`,
		userID, blindIndex, t, tenantID,
	)
	if err != nil {
		return fmt.Errorf("update last contacted: %w", err)
	}
	return nil
}

// BackfillEncryptedAddresses migrates any rows that still have a
// plaintext `address` and a NULL `address_encrypted` to the new
// encrypted format. Called on backend startup. Idempotent — rows that
// have already been backfilled are skipped.
//
// For each row needing backfill, the function looks up the user's
// pubkey, encrypts the cleartext address to it, computes the blind
// index, and writes both. The plaintext column is then NULLed out so
// nothing remains at rest. The legacy unique constraint on
// (user_id, address) is satisfied as long as we NULL the column in the
// same UPDATE that populates the new fields (NULLs don't conflict).
//
// Returns the number of rows backfilled.
func (s *ContactsStore) BackfillEncryptedAddresses(ctx context.Context, authStore *AuthStore) (int, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, user_id, address FROM contacts
		 WHERE address IS NOT NULL AND address_encrypted IS NULL
		 LIMIT 5000`,
	)
	if err != nil {
		return 0, fmt.Errorf("backfill: list pending contacts: %w", err)
	}
	type pending struct {
		id      uuid.UUID
		userID  uuid.UUID
		address string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.userID, &p.address); err != nil {
			rows.Close()
			return 0, fmt.Errorf("backfill: scan: %w", err)
		}
		todo = append(todo, p)
	}
	rows.Close()

	// Cache user keys to avoid repeated lookups for the same user.
	type cachedKeys struct {
		pubKey    []byte
		kemPubKey []byte
	}
	keyCache := make(map[uuid.UUID]cachedKeys)
	getKeys := func(uid uuid.UUID) (cachedKeys, error) {
		if k, ok := keyCache[uid]; ok {
			return k, nil
		}
		u, err := authStore.GetUserByID(ctx, uid)
		if err != nil {
			return cachedKeys{}, err
		}
		k := cachedKeys{pubKey: u.PublicKeyEncryption, kemPubKey: u.PublicKeyKEM}
		keyCache[uid] = k
		return k, nil
	}

	count := 0
	for _, p := range todo {
		keys, err := getKeys(p.userID)
		if err != nil {
			// User row missing or unreadable — skip and let a future
			// run try again rather than crashing the whole backfill.
			continue
		}
		enc, err := EncryptAddressForUserHybrid(keys.pubKey, keys.kemPubKey, p.address)
		if err != nil {
			continue
		}
		blindIndex := ComputeAddressBlindIndex(BlindScopeContact, p.userID, p.address)

		// Check if a sibling row with the same blind_index already exists
		// for this user. That's the duplicate scenario: a pre-migration
		// row with NULL blind_index AND a post-migration auto-add row
		// with the same canonical address. The post-migration row already
		// has the blind_index set, so we MERGE the legacy row INTO the
		// canonical one and then DELETE the legacy. We can't just delete
		// the legacy because it may carry data the canonical lacks
		// (encrypted name, last_contacted, trusted flag, PGP/S-MIME keys,
		// contact_group_members entries).
		var canonicalID uuid.UUID
		err = s.DB.Pool.QueryRow(ctx,
			`SELECT id FROM contacts
			 WHERE user_id = $1 AND address_blind_index = $2 AND id != $3
			 LIMIT 1`,
			p.userID, blindIndex, p.id,
		).Scan(&canonicalID)
		if err == nil {
			// Merge then drop. All in one transaction so a partial
			// failure can't leave us with half-merged state.
			if mergeErr := s.mergeAndDropDuplicateContact(ctx, p.id, canonicalID); mergeErr != nil {
				slog.Warn("contacts backfill: merge duplicate failed",
					"legacy_id", p.id, "canonical_id", canonicalID, "error", mergeErr)
				continue
			}
			count++
			continue
		}
		// err != nil means no duplicate (pgx.ErrNoRows or another error).
		// In the no-rows case we proceed to UPDATE; any other error gets
		// caught by the UPDATE itself.

		_, err = s.DB.Pool.Exec(ctx,
			`UPDATE contacts SET
				address_encrypted = $2,
				address_ephemeral = $3,
				address_enc_key   = $4,
				address_blind_index = $5,
				address           = NULL
			 WHERE id = $1`,
			p.id, enc.Encrypted, enc.Ephemeral, enc.EncryptedKey, blindIndex,
		)
		if err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// mergeAndDropDuplicateContact merges the metadata of `legacyID` into
// `canonicalID` and then deletes `legacyID`. Both rows must belong to
// the same user (caller's responsibility — we re-check inside the tx
// to be defensive). Specifically:
//
//   - name_encrypted: keep canonical if non-null, else take legacy's
//   - public_key_enc: keep canonical if non-null, else take legacy's
//   - pgp_public_key: keep canonical if non-empty, else take legacy's
//   - smime_certificate: keep canonical if non-null, else take legacy's
//   - last_contacted: take MAX of the two
//   - trusted: OR of the two (true wins)
//   - created_at: take MIN of the two (preserve the earliest)
//   - contact_group_members: rewire from legacy to canonical, deduping
//     on conflict so the canonical doesn't double-count groups it's
//     already in
//
// All in one transaction. The legacy row is deleted last; the
// contact_group_members FK has ON DELETE CASCADE so any rows we miss
// during rewiring would be wiped — by re-pointing first and then
// deleting we make sure no group membership is silently lost.
func (s *ContactsStore) mergeAndDropDuplicateContact(ctx context.Context, legacyID, canonicalID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin merge tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Defensive ownership check — both rows must belong to the same user.
	var legacyUser, canonicalUser uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT user_id FROM contacts WHERE id = $1`, legacyID).Scan(&legacyUser); err != nil {
		return fmt.Errorf("lookup legacy user: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT user_id FROM contacts WHERE id = $1`, canonicalID).Scan(&canonicalUser); err != nil {
		return fmt.Errorf("lookup canonical user: %w", err)
	}
	if legacyUser != canonicalUser {
		return fmt.Errorf("merge across users blocked: legacy=%s canonical=%s", legacyUser, canonicalUser)
	}

	// Merge fields from legacy into canonical.
	_, err = tx.Exec(ctx,
		`UPDATE contacts AS c SET
			name_encrypted    = COALESCE(c.name_encrypted, l.name_encrypted),
			public_key_enc    = COALESCE(c.public_key_enc, l.public_key_enc),
			pgp_public_key    = CASE WHEN c.pgp_public_key IS NULL OR c.pgp_public_key = '' THEN l.pgp_public_key ELSE c.pgp_public_key END,
			smime_certificate = COALESCE(c.smime_certificate, l.smime_certificate),
			last_contacted    = GREATEST(c.last_contacted, l.last_contacted),
			trusted           = c.trusted OR l.trusted,
			created_at        = LEAST(c.created_at, l.created_at)
		 FROM contacts AS l
		 WHERE c.id = $1 AND l.id = $2`,
		canonicalID, legacyID,
	)
	if err != nil {
		return fmt.Errorf("merge contact fields: %w", err)
	}

	// Rewire contact_group_members from legacy → canonical. Use
	// ON CONFLICT DO NOTHING so we drop redundant rows when canonical
	// is already a member of the same group, instead of failing on
	// the (group_id, contact_id) primary key.
	_, err = tx.Exec(ctx,
		`INSERT INTO contact_group_members (group_id, contact_id)
		 SELECT group_id, $2 FROM contact_group_members WHERE contact_id = $1
		 ON CONFLICT (group_id, contact_id) DO NOTHING`,
		legacyID, canonicalID,
	)
	if err != nil {
		return fmt.Errorf("rewire group members: %w", err)
	}

	// Now safe to delete the legacy row — all metadata is on canonical
	// and all group memberships are pointed at canonical. The cascading
	// delete on contact_group_members removes the original (legacy)
	// rows we just copied.
	if _, err := tx.Exec(ctx, `DELETE FROM contacts WHERE id = $1`, legacyID); err != nil {
		return fmt.Errorf("delete legacy row: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit merge tx: %w", err)
	}
	return nil
}
