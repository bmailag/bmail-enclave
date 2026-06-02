package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GroupStore provides persistence for E2E private groups (ADR-012). It stores
// the group public key and per-member wrapped private-key blobs; it never holds
// the group private key or any plaintext.
type GroupStore struct {
	DB *DB
}

// NewGroupStore wraps an existing *DB connection.
func NewGroupStore(db *DB) *GroupStore {
	return &GroupStore{DB: db}
}

// ErrGroupNotFound is returned when a group lookup misses.
var ErrGroupNotFound = errors.New("group not found")

// CreateGroup inserts a new group with its public key and initial members in a
// single transaction. ktEpoch is the KT tree epoch the public-key leaf was
// published at. Members carry their wrapped key + kem_output (offline-OK) and
// admin flag; joined_at_epoch for all initial members is keyEpoch (0 at create).
func (s *GroupStore) CreateGroup(ctx context.Context, g *Group, members []GroupMember) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if g.GroupID == uuid.Nil {
		g.GroupID = uuid.New()
	}
	postingPolicy := g.PostingPolicy
	if postingPolicy != "anyone" {
		postingPolicy = "members"
	}
	g.PostingPolicy = postingPolicy
	err = tx.QueryRow(ctx,
		`INSERT INTO groups (group_id, tenant_id, address, public_key_x25519, public_key_kem, kt_epoch, key_epoch, status, posting_policy)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8) RETURNING created_at`,
		g.GroupID, g.TenantID, g.Address, g.PublicKeyX25519, g.PublicKeyKEM, g.KTEpoch, g.KeyEpoch, postingPolicy,
	).Scan(&g.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert group: %w", err)
	}

	for _, m := range members {
		if _, err := tx.Exec(ctx,
			`INSERT INTO group_members (group_id, member_user_id, wrapped_private_key, kem_output, is_admin, joined_at_epoch)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			g.GroupID, m.MemberUserID, m.WrappedPrivateKey, m.KEMOutput, m.IsAdmin, g.KeyEpoch,
		); err != nil {
			return fmt.Errorf("insert member %s: %w", m.MemberUserID, err)
		}
	}
	return tx.Commit(ctx)
}

// GetGroupByID returns the group row (without members).
func (s *GroupStore) GetGroupByID(ctx context.Context, groupID uuid.UUID) (*Group, error) {
	return s.scanGroup(ctx, `WHERE group_id = $1`, groupID)
}

// GetGroupByAddress returns the group row for a group address (lowercased).
func (s *GroupStore) GetGroupByAddress(ctx context.Context, address string) (*Group, error) {
	return s.scanGroup(ctx, `WHERE address = $1`, address)
}

func (s *GroupStore) scanGroup(ctx context.Context, where string, arg interface{}) (*Group, error) {
	var g Group
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT group_id, tenant_id, address, public_key_x25519, public_key_kem, kt_epoch, key_epoch,
		        pending_keygen_user_id, status, posting_policy, created_at
		 FROM groups `+where, arg,
	).Scan(&g.GroupID, &g.TenantID, &g.Address, &g.PublicKeyX25519, &g.PublicKeyKEM, &g.KTEpoch, &g.KeyEpoch,
		&g.PendingKeygenUserID, &g.Status, &g.PostingPolicy, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	return &g, nil
}

// ListGroups returns all groups for a tenant (without members).
func (s *GroupStore) ListGroups(ctx context.Context, tenantID uuid.UUID) ([]Group, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT group_id, tenant_id, address, public_key_x25519, public_key_kem, kt_epoch, key_epoch,
		        pending_keygen_user_id, status, posting_policy, created_at
		 FROM groups WHERE tenant_id = $1 ORDER BY address`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.GroupID, &g.TenantID, &g.Address, &g.PublicKeyX25519, &g.PublicKeyKEM,
			&g.KTEpoch, &g.KeyEpoch, &g.PendingKeygenUserID, &g.Status, &g.PostingPolicy, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetPostingPolicy updates who may post to the group ('members' | 'anyone').
func (s *GroupStore) SetPostingPolicy(ctx context.Context, groupID uuid.UUID, policy string) error {
	if policy != "anyone" {
		policy = "members"
	}
	_, err := s.DB.Pool.Exec(ctx, `UPDATE groups SET posting_policy = $2 WHERE group_id = $1`, groupID, policy)
	if err != nil {
		return fmt.Errorf("set posting policy: %w", err)
	}
	return nil
}

// DeleteGroup removes a group and (via FK cascade) its members and epoch keys.
func (s *GroupStore) DeleteGroup(ctx context.Context, groupID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx, `DELETE FROM groups WHERE group_id = $1`, groupID)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// ListMembers returns the membership of a group. The server may know membership;
// it is hidden from senders/members only at the API layer.
func (s *GroupStore) ListMembers(ctx context.Context, groupID uuid.UUID) ([]GroupMember, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT group_id, member_user_id, wrapped_private_key, kem_output, is_admin, joined_at_epoch, added_at
		 FROM group_members WHERE group_id = $1 ORDER BY added_at`, groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.GroupID, &m.MemberUserID, &m.WrappedPrivateKey, &m.KEMOutput,
			&m.IsAdmin, &m.JoinedAtEpoch, &m.AddedAt); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMember returns a single membership row, or ErrGroupNotFound if absent.
func (s *GroupStore) GetMember(ctx context.Context, groupID, userID uuid.UUID) (*GroupMember, error) {
	var m GroupMember
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT group_id, member_user_id, wrapped_private_key, kem_output, is_admin, joined_at_epoch, added_at
		 FROM group_members WHERE group_id = $1 AND member_user_id = $2`, groupID, userID,
	).Scan(&m.GroupID, &m.MemberUserID, &m.WrappedPrivateKey, &m.KEMOutput, &m.IsAdmin, &m.JoinedAtEpoch, &m.AddedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get member: %w", err)
	}
	return &m, nil
}

// IsGroupAdmin reports whether userID is an admin of the group.
func (s *GroupStore) IsGroupAdmin(ctx context.Context, groupID, userID uuid.UUID) (bool, error) {
	var isAdmin bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT is_admin FROM group_members WHERE group_id = $1 AND member_user_id = $2`, groupID, userID,
	).Scan(&isAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is group admin: %w", err)
	}
	return isAdmin, nil
}

// GetEpochKey returns a member's wrapped key for a SPECIFIC past key_epoch from
// the archive (group_epoch_keys), so a reader can decrypt mail that was
// encrypted under a now-superseded group key. Returns ErrGroupNotFound if there
// is no archived key for that (group, member, epoch).
func (s *GroupStore) GetEpochKey(ctx context.Context, groupID, userID uuid.UUID, epoch int) (wrapped, kemOutput []byte, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT wrapped_private_key, kem_output FROM group_epoch_keys
		 WHERE group_id = $1 AND member_user_id = $2 AND key_epoch = $3`,
		groupID, userID, epoch,
	).Scan(&wrapped, &kemOutput)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrGroupNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get epoch key: %w", err)
	}
	return wrapped, kemOutput, nil
}

// AddMember inserts a member with the current epoch's wrapped key (offline-OK)
// and joined_at_epoch set to the group's current key_epoch (no pre-join history).
func (s *GroupStore) AddMember(ctx context.Context, m *GroupMember, joinedAtEpoch int) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO group_members (group_id, member_user_id, wrapped_private_key, kem_output, is_admin, joined_at_epoch)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		m.GroupID, m.MemberUserID, m.WrappedPrivateKey, m.KEMOutput, m.IsAdmin, joinedAtEpoch,
	)
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// RemoveMember deletes a member. Crypto removal (rotation) is a separate step;
// the caller cuts off delivery immediately by removing the row, then rotates.
func (s *GroupStore) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND member_user_id = $2`, groupID, userID)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// SetMemberAdmin flips a member's admin flag (domain owner appoints group admins).
func (s *GroupStore) SetMemberAdmin(ctx context.Context, groupID, userID uuid.UUID, isAdmin bool) error {
	ct, err := s.DB.Pool.Exec(ctx,
		`UPDATE group_members SET is_admin = $3 WHERE group_id = $1 AND member_user_id = $2`,
		groupID, userID, isAdmin)
	if err != nil {
		return fmt.Errorf("set member admin: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// SetMemberWrappedKey stores the current-epoch wrapped private key + kem_output
// for a member — used by a group admin (leader) distributing the key. Offline-OK:
// the recipient need not be online.
func (s *GroupStore) SetMemberWrappedKey(ctx context.Context, groupID, userID uuid.UUID, wrapped, kemOutput []byte) error {
	ct, err := s.DB.Pool.Exec(ctx,
		`UPDATE group_members SET wrapped_private_key = $3, kem_output = $4
		 WHERE group_id = $1 AND member_user_id = $2`,
		groupID, userID, wrapped, kemOutput)
	if err != nil {
		return fmt.Errorf("set member wrapped key: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// RotateGroupKey archives the current per-member keys into group_epoch_keys,
// bumps key_epoch, sets the new public key + kt_epoch, marks the named admin as
// responsible for finishing distribution (pending_keygen_user_id), and clears
// live wrapped keys for all remaining members so the leader repopulates them.
// All in one transaction (mirrors sojooo's rotateConvKey, scoped to admins).
func (s *GroupStore) RotateGroupKey(ctx context.Context, groupID, leaderID uuid.UUID, newX25519, newKEM []byte, newKTEpoch int64) (newKeyEpoch int, err error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var curEpoch int
	if err := tx.QueryRow(ctx,
		`SELECT key_epoch FROM groups WHERE group_id = $1 FOR UPDATE`, groupID,
	).Scan(&curEpoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrGroupNotFound
		}
		return 0, fmt.Errorf("lock group: %w", err)
	}

	// Archive current keys for members who have one (live key or a pending kem).
	if _, err := tx.Exec(ctx,
		`INSERT INTO group_epoch_keys (group_id, member_user_id, key_epoch, wrapped_private_key, kem_output)
		 SELECT group_id, member_user_id, $2, wrapped_private_key, kem_output
		 FROM group_members
		 WHERE group_id = $1 AND (wrapped_private_key IS NOT NULL OR kem_output IS NOT NULL)
		 ON CONFLICT (group_id, member_user_id, key_epoch) DO NOTHING`,
		groupID, curEpoch,
	); err != nil {
		return 0, fmt.Errorf("archive epoch keys: %w", err)
	}

	newKeyEpoch = curEpoch + 1
	if _, err := tx.Exec(ctx,
		`UPDATE groups SET key_epoch = $2, public_key_x25519 = $3, public_key_kem = $4,
		        kt_epoch = $5, pending_keygen_user_id = $6, status = 'rotation_pending'
		 WHERE group_id = $1`,
		groupID, newKeyEpoch, newX25519, newKEM, newKTEpoch, leaderID,
	); err != nil {
		return 0, fmt.Errorf("update group rotation: %w", err)
	}

	// Clear live keys so the leader repopulates for the new epoch.
	if _, err := tx.Exec(ctx,
		`UPDATE group_members SET wrapped_private_key = NULL, kem_output = NULL WHERE group_id = $1`,
		groupID,
	); err != nil {
		return 0, fmt.Errorf("clear member keys: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return newKeyEpoch, nil
}

// ClearPendingKeygen marks a rekey distribution complete: clears the pending
// guard and returns the group to active, but only if the caller is the named
// leader and the epoch still matches (stale-rotation safe).
func (s *GroupStore) ClearPendingKeygen(ctx context.Context, groupID, leaderID uuid.UUID, keyEpoch int) error {
	ct, err := s.DB.Pool.Exec(ctx,
		`UPDATE groups SET pending_keygen_user_id = NULL, status = 'active'
		 WHERE group_id = $1 AND pending_keygen_user_id = $2 AND key_epoch = $3`,
		groupID, leaderID, keyEpoch)
	if err != nil {
		return fmt.Errorf("clear pending keygen: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrGroupNotFound // not the leader, or epoch moved on
	}
	return nil
}
