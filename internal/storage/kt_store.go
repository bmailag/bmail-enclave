package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// KTLeaf represents a row in the kt_leaves table.
type KTLeaf struct {
	LeafID     int64     `db:"leaf_id"`
	UserID     uuid.UUID `db:"user_id"`
	TenantID   uuid.UUID `db:"tenant_id"`
	Epoch      int64     `db:"epoch"`
	PubkeyHash []byte    `db:"pubkey_hash"`
	CreatedAt  time.Time `db:"created_at"`
}

// KTRoot represents a row in the kt_roots table.
type KTRoot struct {
	Epoch     int64     `db:"epoch"`
	TenantID  uuid.UUID `db:"tenant_id"`
	RootHash  []byte    `db:"root_hash"`
	Signature []byte    `db:"signature"`
	TreeSize  int64     `db:"tree_size"`
	CreatedAt time.Time `db:"created_at"`
}

// KTStore provides persistence for key transparency leaves and roots.
type KTStore struct {
	db *DB
}

// NewKTStore wraps an existing *DB connection.
func NewKTStore(db *DB) *KTStore {
	return &KTStore{db: db}
}

// GetLatestEpoch returns the latest signed epoch number for a tenant.
func (s *KTStore) GetLatestEpoch(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var latest int64
	err := s.db.Pool.QueryRow(ctx,
		`SELECT epoch FROM kt_roots WHERE tenant_id = $1 ORDER BY epoch DESC LIMIT 1`,
		tenantID,
	).Scan(&latest)
	if err != nil {
		return 0, fmt.Errorf("no epochs for tenant: %w", err)
	}
	return latest, nil
}

// NextEpoch returns the next epoch number for a tenant (latest root epoch + 1, or 1 if none).
func (s *KTStore) NextEpoch(ctx context.Context, tenantID uuid.UUID) int64 {
	var latest int64
	err := s.db.Pool.QueryRow(ctx,
		`SELECT epoch FROM kt_roots WHERE tenant_id = $1 ORDER BY epoch DESC LIMIT 1`,
		tenantID,
	).Scan(&latest)
	if err != nil {
		return 1
	}
	return latest + 1
}

// AddOrUpdateLeaf inserts a leaf, or updates pubkey_hash if one already exists
// for (user_id, epoch). Safe ONLY for the pending (not-yet-signed) epoch — that
// epoch has no signed root yet, so revising a leaf before AdvanceEpoch commits
// it is sound. Used for group key publication, where a group can be created and
// then re-keyed (rotated) within a single KT epoch.
func (s *KTStore) AddOrUpdateLeaf(ctx context.Context, userID, tenantID uuid.UUID, epoch int64, pubkeyHash []byte) error {
	_, err := s.db.Pool.Exec(ctx,
		`INSERT INTO kt_leaves (user_id, tenant_id, epoch, pubkey_hash) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_id, epoch) DO UPDATE SET pubkey_hash = EXCLUDED.pubkey_hash`,
		userID, tenantID, epoch, pubkeyHash,
	)
	if err != nil {
		return fmt.Errorf("upsert kt_leaf: %w", err)
	}
	return nil
}

// AddLeaf inserts a new leaf into kt_leaves and returns the generated leaf_id.
func (s *KTStore) AddLeaf(ctx context.Context, userID, tenantID uuid.UUID, epoch int64, pubkeyHash []byte) (int64, error) {
	var leafID int64
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO kt_leaves (user_id, tenant_id, epoch, pubkey_hash) VALUES ($1, $2, $3, $4) RETURNING leaf_id`,
		userID, tenantID, epoch, pubkeyHash,
	).Scan(&leafID)
	if err != nil {
		return 0, fmt.Errorf("insert kt_leaf: %w", err)
	}
	return leafID, nil
}

// GetLeaves returns all leaves for a given epoch and tenant ordered by leaf_id.
func (s *KTStore) GetLeaves(ctx context.Context, tenantID uuid.UUID, epoch int64) ([]KTLeaf, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT leaf_id, user_id, tenant_id, epoch, pubkey_hash, created_at FROM kt_leaves WHERE tenant_id = $1 AND epoch = $2 ORDER BY leaf_id`,
		tenantID, epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("query kt_leaves: %w", err)
	}
	defer rows.Close()

	var leaves []KTLeaf
	for rows.Next() {
		var l KTLeaf
		if err := rows.Scan(&l.LeafID, &l.UserID, &l.TenantID, &l.Epoch, &l.PubkeyHash, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan kt_leaf: %w", err)
		}
		leaves = append(leaves, l)
	}
	return leaves, rows.Err()
}

// GetLeavesByUser returns all leaves for the given user across all epochs, scoped to tenant.
func (s *KTStore) GetLeavesByUser(ctx context.Context, tenantID, userID uuid.UUID) ([]KTLeaf, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT leaf_id, user_id, tenant_id, epoch, pubkey_hash, created_at FROM kt_leaves WHERE tenant_id = $1 AND user_id = $2 ORDER BY epoch, leaf_id`,
		tenantID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("query kt_leaves by user: %w", err)
	}
	defer rows.Close()

	var leaves []KTLeaf
	for rows.Next() {
		var l KTLeaf
		if err := rows.Scan(&l.LeafID, &l.UserID, &l.TenantID, &l.Epoch, &l.PubkeyHash, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan kt_leaf: %w", err)
		}
		leaves = append(leaves, l)
	}
	return leaves, rows.Err()
}

// StoreRoot inserts a signed root for the given epoch and tenant.
// Returns a clear error if a root for this epoch/tenant already exists.
func (s *KTStore) StoreRoot(ctx context.Context, tenantID uuid.UUID, epoch int64, rootHash, signature []byte, treeSize ...int64) error {
	var size int64
	if len(treeSize) > 0 {
		size = treeSize[0]
	}
	tag, err := s.db.Pool.Exec(ctx,
		`INSERT INTO kt_roots (epoch, tenant_id, root_hash, signature, tree_size) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, epoch) DO NOTHING`,
		epoch, tenantID, rootHash, signature, size,
	)
	if err != nil {
		return fmt.Errorf("insert kt_root: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("kt root for epoch %d already exists", epoch)
	}
	return nil
}

// GetRoot returns the signed root for a specific epoch and tenant.
func (s *KTStore) GetRoot(ctx context.Context, tenantID uuid.UUID, epoch int64) (*KTRoot, error) {
	var r KTRoot
	err := s.db.Pool.QueryRow(ctx,
		`SELECT epoch, tenant_id, root_hash, signature, tree_size, created_at FROM kt_roots WHERE tenant_id = $1 AND epoch = $2`,
		tenantID, epoch,
	).Scan(&r.Epoch, &r.TenantID, &r.RootHash, &r.Signature, &r.TreeSize, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get kt_root: %w", err)
	}
	return &r, nil
}

// GetLatestRoot returns the most recent signed root (highest epoch) for a tenant.
func (s *KTStore) GetLatestRoot(ctx context.Context, tenantID uuid.UUID) (*KTRoot, error) {
	var r KTRoot
	err := s.db.Pool.QueryRow(ctx,
		`SELECT epoch, tenant_id, root_hash, signature, tree_size, created_at FROM kt_roots WHERE tenant_id = $1 ORDER BY epoch DESC LIMIT 1`,
		tenantID,
	).Scan(&r.Epoch, &r.TenantID, &r.RootHash, &r.Signature, &r.TreeSize, &r.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get latest kt_root: %w", err)
	}
	return &r, nil
}

// EpochData contains the inputs and output of an atomic epoch advancement.
type EpochData struct {
	Epoch  int64
	Leaves []KTLeaf
}

// AdvanceEpochTx runs the read-compute-write cycle for epoch advancement inside
// a SERIALIZABLE transaction, preventing concurrent races.
// computeRoot receives the epoch and sorted leaves and must return (rootHash, signature, treeSize).
func (s *KTStore) AdvanceEpochTx(ctx context.Context, tenantID uuid.UUID, computeRoot func(epoch int64, leaves []KTLeaf) (rootHash, signature []byte, treeSize int64, err error)) (int64, error) {
	tx, err := s.db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Determine current epoch.
	var currentEpoch int64
	err = tx.QueryRow(ctx,
		`SELECT epoch FROM kt_roots WHERE tenant_id = $1 ORDER BY epoch DESC LIMIT 1`,
		tenantID,
	).Scan(&currentEpoch)
	if err != nil {
		currentEpoch = 0 // no root yet
	}
	currentEpoch++

	// Carry forward leaves from the previous epoch that don't exist in the new epoch.
	if currentEpoch > 1 {
		_, err = tx.Exec(ctx,
			`INSERT INTO kt_leaves (user_id, tenant_id, epoch, pubkey_hash)
			 SELECT user_id, tenant_id, $1, pubkey_hash FROM kt_leaves
			 WHERE tenant_id = $2 AND epoch = $3
			   AND user_id NOT IN (SELECT user_id FROM kt_leaves WHERE tenant_id = $2 AND epoch = $1)`,
			currentEpoch, tenantID, currentEpoch-1,
		)
		if err != nil {
			return 0, fmt.Errorf("carry forward leaves: %w", err)
		}
	}

	// Get leaves for the new epoch.
	rows, err := tx.Query(ctx,
		`SELECT leaf_id, user_id, tenant_id, epoch, pubkey_hash, created_at FROM kt_leaves WHERE tenant_id = $1 AND epoch = $2 ORDER BY leaf_id`,
		tenantID, currentEpoch,
	)
	if err != nil {
		return 0, fmt.Errorf("query leaves in tx: %w", err)
	}
	defer rows.Close()

	var leaves []KTLeaf
	for rows.Next() {
		var l KTLeaf
		if err := rows.Scan(&l.LeafID, &l.UserID, &l.TenantID, &l.Epoch, &l.PubkeyHash, &l.CreatedAt); err != nil {
			return 0, fmt.Errorf("scan leaf in tx: %w", err)
		}
		leaves = append(leaves, l)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("rows err: %w", err)
	}
	if len(leaves) == 0 {
		return 0, fmt.Errorf("no leaves for epoch %d", currentEpoch)
	}

	// Let caller compute the Merkle root and signature.
	rootHash, sig, treeSize, err := computeRoot(currentEpoch, leaves)
	if err != nil {
		return 0, err
	}

	// Store the root inside the same transaction.
	tag, err := tx.Exec(ctx,
		`INSERT INTO kt_roots (epoch, tenant_id, root_hash, signature, tree_size) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, epoch) DO NOTHING`,
		currentEpoch, tenantID, rootHash, sig, treeSize,
	)
	if err != nil {
		return 0, fmt.Errorf("insert root in tx: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, fmt.Errorf("kt root for epoch %d already exists", currentEpoch)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}
	return currentEpoch, nil
}

// GetTenantByUserID looks up the tenant_id for a user from kt_leaves.
// Returns the tenant_id from the most recent leaf entry for the given user.
func (s *KTStore) GetTenantByUserID(ctx context.Context, userID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := s.db.Pool.QueryRow(ctx,
		`SELECT tenant_id FROM kt_leaves WHERE user_id = $1 ORDER BY epoch DESC LIMIT 1`,
		userID,
	).Scan(&tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("get tenant by user_id: %w", err)
	}
	return tenantID, nil
}

// GetRootsSince returns all signed roots created after the given timestamp, ordered by epoch.
func (s *KTStore) GetRootsSince(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]KTRoot, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT epoch, tenant_id, root_hash, signature, tree_size, created_at FROM kt_roots WHERE tenant_id = $1 AND created_at > $2 ORDER BY epoch`,
		tenantID, since,
	)
	if err != nil {
		return nil, fmt.Errorf("query kt_roots since: %w", err)
	}
	defer rows.Close()

	var roots []KTRoot
	for rows.Next() {
		var r KTRoot
		if err := rows.Scan(&r.Epoch, &r.TenantID, &r.RootHash, &r.Signature, &r.TreeSize, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan kt_root: %w", err)
		}
		roots = append(roots, r)
	}
	return roots, rows.Err()
}
