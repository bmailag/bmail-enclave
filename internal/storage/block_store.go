package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// BlockStore wraps DB and provides blocked sender operations.
type BlockStore struct {
	DB *DB
}

// NewBlockStore returns a new BlockStore.
func NewBlockStore(db *DB) *BlockStore {
	return &BlockStore{DB: db}
}

// blockedColumns is the column list for blocked_sender SELECTs.
const blockedColumns = `id, user_id, tenant_id,
	COALESCE(sender_address, ''),
	COALESCE(sender_encrypted, ''::bytea),
	COALESCE(sender_ephemeral, ''::bytea),
	COALESCE(sender_enc_key, ''::bytea),
	COALESCE(sender_blind_index, ''),
	created_at`

// BlockSender adds a sender to the block list. The caller must look up
// the user's pubkey and provide the cleartext address — the store
// computes the blind index and encrypts to the pubkey before storing.
//
// Server-internal cleartext is acceptable here: the user typed the
// address into the API request, and the cleartext is discarded after
// this call. Nothing plaintext is persisted.
func (s *BlockStore) BlockSender(ctx context.Context, userID, tenantID uuid.UUID, userPubKey, userKEMPubKey []byte, senderAddress string) error {
	enc, err := EncryptAddressForUserHybrid(userPubKey, userKEMPubKey, senderAddress)
	if err != nil {
		return fmt.Errorf("block sender: encrypt: %w", err)
	}
	blindIndex := ComputeAddressBlindIndex(BlindScopeBlockSender, userID, senderAddress)
	_, err = s.DB.Pool.Exec(ctx,
		`INSERT INTO blocked_senders (
			id, user_id, tenant_id,
			sender_encrypted, sender_ephemeral, sender_enc_key, sender_blind_index
		 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (user_id, sender_blind_index) WHERE sender_blind_index IS NOT NULL DO NOTHING`,
		uuid.New(), userID, tenantID,
		enc.Encrypted, enc.Ephemeral, enc.EncryptedKey, blindIndex,
	)
	if err != nil {
		return fmt.Errorf("block sender: %w", err)
	}
	return nil
}

// UnblockSender removes a sender from the block list, looking up by
// blind index computed from the cleartext address.
func (s *BlockStore) UnblockSender(ctx context.Context, userID uuid.UUID, senderAddress string) error {
	blindIndex := ComputeAddressBlindIndex(BlindScopeBlockSender, userID, senderAddress)
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM blocked_senders WHERE user_id = $1 AND sender_blind_index = $2`,
		userID, blindIndex,
	)
	if err != nil {
		return fmt.Errorf("unblock sender: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sender not found in block list")
	}
	return nil
}

// ListBlocked returns all blocked senders for a user. Address is
// encrypted; clients decrypt locally for display.
func (s *BlockStore) ListBlocked(ctx context.Context, userID, tenantID uuid.UUID) ([]*BlockedSender, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT `+blockedColumns+`
		 FROM blocked_senders WHERE user_id = $1 AND tenant_id = $2 ORDER BY created_at DESC`,
		userID, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list blocked: %w", err)
	}
	defer rows.Close()

	var blocked []*BlockedSender
	for rows.Next() {
		b := &BlockedSender{}
		if err := rows.Scan(
			&b.ID, &b.UserID, &b.TenantID,
			&b.SenderAddress,
			&b.SenderEncrypted, &b.SenderEphemeral, &b.SenderEncKey, &b.SenderBlindIndex,
			&b.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan blocked: %w", err)
		}
		blocked = append(blocked, b)
	}
	return blocked, rows.Err()
}

// IsBlocked checks if a sender is blocked by a user. Computes the
// blind index from the cleartext address provided by the caller —
// typically the smtp-inbound enclave with the SMTP envelope sender.
func (s *BlockStore) IsBlocked(ctx context.Context, userID uuid.UUID, senderAddress string) (bool, error) {
	blindIndex := ComputeAddressBlindIndex(BlindScopeBlockSender, userID, senderAddress)
	var exists bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM blocked_senders WHERE user_id = $1 AND sender_blind_index = $2)`,
		userID, blindIndex,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check blocked: %w", err)
	}
	return exists, nil
}

// BackfillEncryptedSenders migrates any rows that still have a plaintext
// sender_address and a NULL sender_encrypted to the new encrypted format.
// Symmetric to ContactsStore.BackfillEncryptedAddresses.
func (s *BlockStore) BackfillEncryptedSenders(ctx context.Context, authStore *AuthStore) (int, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT id, user_id, sender_address FROM blocked_senders
		 WHERE sender_address IS NOT NULL AND sender_encrypted IS NULL
		 LIMIT 5000`,
	)
	if err != nil {
		return 0, fmt.Errorf("backfill: list pending: %w", err)
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
			continue
		}
		enc, err := EncryptAddressForUserHybrid(keys.pubKey, keys.kemPubKey, p.address)
		if err != nil {
			continue
		}
		blindIndex := ComputeAddressBlindIndex(BlindScopeBlockSender, p.userID, p.address)
		_, err = s.DB.Pool.Exec(ctx,
			`UPDATE blocked_senders SET
				sender_encrypted = $2,
				sender_ephemeral = $3,
				sender_enc_key   = $4,
				sender_blind_index = $5,
				sender_address   = NULL
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
