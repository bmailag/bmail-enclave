package storage

import (
	"context"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StripPlusTag removes the +tag portion from an email address.
// e.g., "user+shopping@bmail.ag" → "user@bmail.ag"
func StripPlusTag(address string) string {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return address
	}
	local := address[:at]
	domain := address[at:]
	if plus := strings.Index(local, "+"); plus >= 0 {
		local = local[:plus]
	}
	return local + domain
}

// Lifecycle account_status values. The CHECK constraint in migration
// 094 enforces the same set at the DB level; keep these in sync.
const (
	StatusActive            = "active"
	StatusPaymentFailed     = "payment_failed"
	StatusLapsedToFree      = "lapsed_to_free"
	StatusPruneWarned       = "prune_warned"
	StatusPruning           = "pruning"
	StatusTombstone         = "tombstone"
	StatusDeletedTombstone  = "deleted_tombstone"
	// Legacy values retained for back-compat — no new code should write
	// these; the cleanup cron sweeps stale rows.
	StatusPendingPayment = "pending_payment"
	StatusSuspended      = "suspended"
	StatusPurgePending   = "purge_pending"
	StatusDeletionPending = "deletion_pending"
)

// tokenHMACKey is the server-side HMAC key for session and refresh token hashing.
// Must be set via InitTokenHMACKey before any session operations.
// If nil, falls back to plain SHA-256 (development only).
// F-01 fix: Unified — both session and refresh tokens use the same HMAC key
// with domain-separated contexts to prevent cross-purpose hash collisions.
var tokenHMACKey []byte

// InitTokenHMACKey sets the HMAC key used for both session and refresh token hashing.
// Must be called at startup with a 32-byte key loaded from secure storage.
func InitTokenHMACKey(key []byte) {
	tokenHMACKey = make([]byte, len(key))
	copy(tokenHMACKey, key)
}

// InitRefreshTokenKey is an alias for InitTokenHMACKey for backward compatibility.
func InitRefreshTokenKey(key []byte) {
	InitTokenHMACKey(key)
}

// AuthStore wraps DB and provides authentication-related database operations.
type AuthStore struct {
	DB *DB
}

// NewAuthStore returns a new AuthStore backed by the given DB.
func NewAuthStore(db *DB) *AuthStore {
	return &AuthStore{DB: db}
}

// CreateUser inserts a new user into the users table.
func (s *AuthStore) CreateUser(ctx context.Context, user *User) error {
	recoveryVersion := user.RecoveryVersion
	if recoveryVersion == 0 {
		recoveryVersion = 2 // New accounts default to V2 (HKDF-derived).
	}
	accountStatus := user.AccountStatus
	if accountStatus == "" {
		accountStatus = "active"
	}
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO users (user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch, recovery_version, account_status,
			public_key_kem, encrypted_private_key_kem)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		user.UserID, user.TenantID, user.Address,
		user.PublicKeyEncryption, user.PublicKeySigning,
		user.EncryptedPrivateKey, user.EncryptedRecoveryKey,
		user.OpaqueRegistration, user.KeyEpoch, recoveryVersion, accountStatus,
		user.PublicKeyKEM, user.EncryptedPrivateKeyKEM,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// RegisterUser creates a user and their default folders in a single transaction.
// If any step fails, the entire registration is rolled back.
func (s *AuthStore) RegisterUser(ctx context.Context, user *User) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin registration tx: %w", err)
	}
	defer tx.Rollback(ctx)

	recoveryVersion := user.RecoveryVersion
	if recoveryVersion == 0 {
		recoveryVersion = 2
	}
	accountStatus := user.AccountStatus
	if accountStatus == "" {
		accountStatus = "active"
	}
	accountType := user.AccountType
	if accountType == "" {
		accountType = "primary"
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO users (user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch, recovery_version, account_status,
			opaque_recovery_registration, recovery_blob,
			public_key_kem, encrypted_private_key_kem,
			account_type, dormancy_window_days, valid_until, max_valid_until)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		user.UserID, user.TenantID, user.Address,
		user.PublicKeyEncryption, user.PublicKeySigning,
		user.EncryptedPrivateKey, user.EncryptedRecoveryKey,
		user.OpaqueRegistration, user.KeyEpoch, recoveryVersion, accountStatus,
		user.OpaqueRecoveryRegistration, user.RecoveryBlob,
		user.PublicKeyKEM, user.EncryptedPrivateKeyKEM,
		accountType, user.DormancyWindowDays, user.ValidUntil, user.MaxValidUntil,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	for _, df := range defaultFolderTypes {
		_, err = tx.Exec(ctx,
			`INSERT INTO folders (folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), user.UserID, user.TenantID, []byte(df.Type), df.Type, df.SortOrder,
		)
		if err != nil {
			return fmt.Errorf("create default folder %s: %w", df.Type, err)
		}
	}

	return tx.Commit(ctx)
}

// RegisterInvitedUser creates a user, marks the invitation accepted, assigns
// the member role, and creates default folders — all in a single transaction.
func (s *AuthStore) RegisterInvitedUser(ctx context.Context, user *User, invitationID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin registration tx: %w", err)
	}
	defer tx.Rollback(ctx)

	recoveryVersion := user.RecoveryVersion
	if recoveryVersion == 0 {
		recoveryVersion = 2
	}
	// Invited users are active immediately (domain admin handles billing).
	_, err = tx.Exec(ctx,
		`INSERT INTO users (user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch, recovery_version, account_status,
			opaque_recovery_registration, recovery_blob,
			public_key_kem, encrypted_private_key_kem)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', $11, $12, $13, $14)`,
		user.UserID, user.TenantID, user.Address,
		user.PublicKeyEncryption, user.PublicKeySigning,
		user.EncryptedPrivateKey, user.EncryptedRecoveryKey,
		user.OpaqueRegistration, user.KeyEpoch, recoveryVersion,
		user.OpaqueRecoveryRegistration, user.RecoveryBlob,
		user.PublicKeyKEM, user.EncryptedPrivateKeyKEM,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	// Audit fix F-13: Scope invitation acceptance by tenant_id to prevent
	// cross-tenant invitation reuse if an attacker knows the invitation UUID.
	tag, err := tx.Exec(ctx,
		`UPDATE domain_invitations SET status = 'accepted' WHERE invitation_id = $1 AND tenant_id = $2`,
		invitationID, user.TenantID,
	)
	if err != nil {
		return fmt.Errorf("mark invitation accepted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("invitation not found or tenant mismatch: %s", invitationID)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO tenant_roles (user_id, tenant_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = $3`,
		user.UserID, user.TenantID, "member",
	)
	if err != nil {
		return fmt.Errorf("assign member role: %w", err)
	}

	for _, df := range defaultFolderTypes {
		_, err = tx.Exec(ctx,
			`INSERT INTO folders (folder_id, user_id, tenant_id, name_encrypted, folder_type, sort_order)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New(), user.UserID, user.TenantID, []byte(df.Type), df.Type, df.SortOrder,
		)
		if err != nil {
			return fmt.Errorf("create default folder %s: %w", df.Type, err)
		}
	}

	return tx.Commit(ctx)
}

// GetUserByAddress looks up a user by their email address.
func (s *AuthStore) GetUserByAddress(ctx context.Context, address string) (*User, error) {
	address = strings.ToLower(StripPlusTag(address))
	u := &User{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch,
			recovery_version, created_at, COALESCE(pgp_public_key, ''), COALESCE(tier, 'mail'),
			storage_used_bytes, COALESCE(account_status, 'active'), payment_failed_at,
			stripe_customer_id, stripe_subscription_id,
			totp_secret_encrypted, totp_enabled, totp_backup_codes, deletion_requested_at,
			opaque_recovery_registration, recovery_blob,
			public_key_kem, encrypted_private_key_kem,
			COALESCE(account_type, 'primary'), dormancy_window_days, valid_until, max_valid_until,
			COALESCE(has_fakeid, FALSE), fakeid_minted_at,
			COALESCE(last_activity_at, created_at)
		 FROM users WHERE address = $1`, address,
	).Scan(
		&u.UserID, &u.TenantID, &u.Address,
		&u.PublicKeyEncryption, &u.PublicKeySigning,
		&u.EncryptedPrivateKey, &u.EncryptedRecoveryKey,
		&u.OpaqueRegistration, &u.KeyEpoch, &u.RecoveryVersion,
		&u.CreatedAt, &u.PGPPublicKey, &u.Tier,
		&u.StorageUsedBytes, &u.AccountStatus, &u.PaymentFailedAt,
		&u.StripeCustomerID, &u.StripeSubscriptionID,
		&u.TOTPSecretEncrypted, &u.TOTPEnabled, &u.TOTPBackupCodes, &u.DeletionRequestedAt,
		&u.OpaqueRecoveryRegistration, &u.RecoveryBlob,
		&u.PublicKeyKEM, &u.EncryptedPrivateKeyKEM,
		&u.AccountType, &u.DormancyWindowDays, &u.ValidUntil, &u.MaxValidUntil,
		&u.HasFakeID, &u.FakeIDMintedAt,
		&u.LastActivityAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user not found: %s", address)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by address: %w", err)
	}
	return u, nil
}

// GetUserByID looks up a user by their UUID.
func (s *AuthStore) GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error) {
	u := &User{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch,
			recovery_version, created_at, COALESCE(pgp_public_key, ''), COALESCE(tier, 'mail'),
			storage_used_bytes, COALESCE(account_status, 'active'), payment_failed_at,
			stripe_customer_id, stripe_subscription_id,
			totp_secret_encrypted, totp_enabled, totp_backup_codes, deletion_requested_at,
			opaque_recovery_registration, recovery_blob,
			public_key_kem, encrypted_private_key_kem,
			COALESCE(account_type, 'primary'), dormancy_window_days, valid_until, max_valid_until,
			COALESCE(has_fakeid, FALSE), fakeid_minted_at,
			COALESCE(last_activity_at, created_at)
		 FROM users WHERE user_id = $1`, userID,
	).Scan(
		&u.UserID, &u.TenantID, &u.Address,
		&u.PublicKeyEncryption, &u.PublicKeySigning,
		&u.EncryptedPrivateKey, &u.EncryptedRecoveryKey,
		&u.OpaqueRegistration, &u.KeyEpoch, &u.RecoveryVersion,
		&u.CreatedAt, &u.PGPPublicKey, &u.Tier,
		&u.StorageUsedBytes, &u.AccountStatus, &u.PaymentFailedAt,
		&u.StripeCustomerID, &u.StripeSubscriptionID,
		&u.TOTPSecretEncrypted, &u.TOTPEnabled, &u.TOTPBackupCodes, &u.DeletionRequestedAt,
		&u.OpaqueRecoveryRegistration, &u.RecoveryBlob,
		&u.PublicKeyKEM, &u.EncryptedPrivateKeyKEM,
		&u.AccountType, &u.DormancyWindowDays, &u.ValidUntil, &u.MaxValidUntil,
		&u.HasFakeID, &u.FakeIDMintedAt,
		&u.LastActivityAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user not found: %s", userID)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// ErrFakeIDSlotTaken is returned when a primary attempts to claim their
// Fake ID slot and it's already claimed (has_fakeid = true).
var ErrFakeIDSlotTaken = errors.New("primary already has a fakeid")

// FakeIDMaxLifetime is the hard upper bound on a single Fake ID's life from
// mint. It sets the initial fakeid_allowed_release_at deadline; ratchet
// issuance can push it forward.
const FakeIDMaxLifetime = 60 * 24 * time.Hour

// ClaimFakeIDSlot atomically sets has_fakeid=true, stamps fakeid_minted_at
// = now(), and pins fakeid_allowed_release_at = now() + FakeIDMaxLifetime
// IF and only if has_fakeid is currently FALSE. Returns ErrFakeIDSlotTaken
// if the primary has already minted. Called from the /fakeid-mgmt/mint
// handler before the enclave signs. If the enclave call subsequently fails,
// the caller should call ReleaseFakeIDSlotIfOwned to roll back.
func (s *AuthStore) ClaimFakeIDSlot(ctx context.Context, userID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET has_fakeid = TRUE,
		     fakeid_minted_at = now(),
		     fakeid_allowed_release_at = now() + make_interval(secs => $2)
		 WHERE user_id = $1 AND has_fakeid = FALSE`,
		userID, int64(FakeIDMaxLifetime.Seconds()),
	)
	if err != nil {
		return fmt.Errorf("claim fakeid slot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrFakeIDSlotTaken
	}
	return nil
}

// ReleaseFakeIDSlotIfOwned undoes a failed mint — clears the slot ONLY if
// fakeid_minted_at was set within the last 60 seconds. Caller uses this
// when the enclave sign call errors after a successful ClaimFakeIDSlot.
// The 60s guard prevents accidentally releasing a much older claim.
func (s *AuthStore) ReleaseFakeIDSlotIfOwned(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET has_fakeid = FALSE, fakeid_minted_at = NULL, fakeid_allowed_release_at = NULL
		 WHERE user_id = $1 AND has_fakeid = TRUE
		   AND fakeid_minted_at > now() - INTERVAL '60 seconds'`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("release fakeid slot: %w", err)
	}
	return nil
}

// ExpireFakeIDSlots clears has_fakeid on primaries whose
// fakeid_allowed_release_at deadline has passed. The worker calls this on
// the same cadence as ExpireStaleFakeIDs so primaries whose Fake ID hit
// max lifetime can mint a new one without any manual action. Returns the
// number of rows updated.
func (s *AuthStore) ExpireFakeIDSlots(ctx context.Context) (int, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET has_fakeid = FALSE,
		     fakeid_minted_at = NULL,
		     fakeid_allowed_release_at = NULL
		 WHERE has_fakeid = TRUE
		   AND fakeid_allowed_release_at IS NOT NULL
		   AND fakeid_allowed_release_at < now()`,
	)
	if err != nil {
		return 0, fmt.Errorf("expire fakeid slots: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ExtendFakeIDAllowedRelease pushes fakeid_allowed_release_at forward by
// extensionDays whenever the primary issues a ratchet credential. The Fake
// ID side may or may not redeem it, but the primary's slot stays locked
// for the maximum it *could* be extended to. Monotonic — never shortens
// the deadline.
func (s *AuthStore) ExtendFakeIDAllowedRelease(ctx context.Context, userID uuid.UUID, extensionDays int) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET fakeid_allowed_release_at = GREATEST(
		     COALESCE(fakeid_allowed_release_at, now()),
		     now() + make_interval(days => $2)
		 )
		 WHERE user_id = $1 AND has_fakeid = TRUE`,
		userID, extensionDays,
	)
	if err != nil {
		return fmt.Errorf("extend fakeid allowed release: %w", err)
	}
	return nil
}

// FakeIDPrimaryRow is the minimum data the Phase 2e backfill needs from a
// primary who currently has has_fakeid=TRUE: the user_id to pass into the
// enclave's HMAC tag derivation, and the minted_at to preserve the
// original consumed_at timestamp.
type FakeIDPrimaryRow struct {
	UserID    uuid.UUID
	MintedAt  time.Time
}

// ListUnmigratedFakeIDPrimaries returns primaries with has_fakeid = TRUE
// that the backfill hasn't yet seeded into fakeid_consumed_slots
// (fakeid_migrated = FALSE, migration 090). Ordered by user_id so
// pagination is stable across restarts; the query itself shrinks on
// each iteration because MarkFakeIDMigrated flips the flag after a
// successful enclave seed. Result is empty once every pre-089 primary
// has been mirrored, at which point the backfill goroutine exits in
// milliseconds on every subsequent boot until Phase 5 drops the column.
func (s *AuthStore) ListUnmigratedFakeIDPrimaries(ctx context.Context, limit int) ([]FakeIDPrimaryRow, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT user_id, COALESCE(fakeid_minted_at, now()) AS minted_at
		 FROM users
		 WHERE has_fakeid = TRUE AND fakeid_migrated = FALSE
		 ORDER BY user_id
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list unmigrated fakeid primaries: %w", err)
	}
	defer rows.Close()
	out := make([]FakeIDPrimaryRow, 0, limit)
	for rows.Next() {
		var r FakeIDPrimaryRow
		if err := rows.Scan(&r.UserID, &r.MintedAt); err != nil {
			return nil, fmt.Errorf("scan fakeid primary row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate fakeid primaries: %w", err)
	}
	return out, nil
}

// MarkFakeIDMigrated flips fakeid_migrated = TRUE for a primary the
// backfill has finished seeding. Called once per successful SeedConsumed
// round-trip, so a transient enclave failure leaves the row unmigrated
// and we retry it next boot.
func (s *AuthStore) MarkFakeIDMigrated(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET fakeid_migrated = TRUE WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("mark fakeid migrated: %w", err)
	}
	return nil
}

// AdvanceFakeIDValidUntil sets a Fake ID's valid_until to
// min(now + dormancy_window_days, max_valid_until) with ±2d jitter. Called on
// every successful Fake ID login — login-as-refresh keeps the account alive.
// No-op if the user is not a Fake ID. Returns the new valid_until.
func (s *AuthStore) AdvanceFakeIDValidUntil(ctx context.Context, userID uuid.UUID) (time.Time, error) {
	jitter := jitterSeconds(2 * 24 * 3600)
	var newValidUntil time.Time
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE users
		 SET valid_until = LEAST(
		     now() + (COALESCE(dormancy_window_days, 30) || ' days')::INTERVAL + make_interval(secs => $2),
		     max_valid_until
		 )
		 WHERE user_id = $1 AND account_type = 'fakeid'
		 RETURNING valid_until`,
		userID, jitter,
	).Scan(&newValidUntil)
	if err != nil {
		return time.Time{}, fmt.Errorf("advance valid_until: %w", err)
	}
	return newValidUntil, nil
}

// AdvanceFakeIDMaxValidUntil pushes a Fake ID's max_valid_until forward by
// extensionDays, capped at the current value (monotonically non-decreasing).
// Called after a successful ratchet credential redemption. Returns the new
// max_valid_until.
func (s *AuthStore) AdvanceFakeIDMaxValidUntil(ctx context.Context, userID uuid.UUID, extensionDays int) (time.Time, error) {
	jitter := jitterSeconds(2 * 24 * 3600)
	var newMax time.Time
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE users
		 SET max_valid_until = GREATEST(
		     max_valid_until,
		     now() + make_interval(days => $2) + make_interval(secs => $3)
		 )
		 WHERE user_id = $1 AND account_type = 'fakeid'
		 RETURNING max_valid_until`,
		userID, extensionDays, jitter,
	).Scan(&newMax)
	if err != nil {
		return time.Time{}, fmt.Errorf("advance max_valid_until: %w", err)
	}
	return newMax, nil
}

// ExpireStaleFakeIDs marks every Fake ID whose valid_until has passed as
// purge_pending, letting the existing purge pipeline delete the account.
// Returns the count of newly-expired rows. Called periodically by the worker.
func (s *AuthStore) ExpireStaleFakeIDs(ctx context.Context) (int, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET account_status = 'purge_pending'
		 WHERE account_type = 'fakeid'
		   AND valid_until < now()
		   AND account_status != 'purge_pending'`,
	)
	if err != nil {
		return 0, fmt.Errorf("expire stale fakeids: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// jitterSeconds returns a uniformly random number in [-max, +max] seconds,
// used to fuzz Fake ID expiry dates so exact cadence isn't a fingerprint.
// Uses crypto/rand for the random value.
func jitterSeconds(max int) int64 {
	var b [8]byte
	if _, err := cryptoRand.Read(b[:]); err != nil {
		return 0 // fallback: no jitter; don't panic auth code
	}
	// Unsigned random in [0, 2*max]; subtract max to center around 0.
	n := int64(binary.BigEndian.Uint64(b[:]) % uint64(2*max+1))
	return n - int64(max)
}

// UpdateUserKeys updates a user's encrypted keys and OPAQUE registration record.
func (s *AuthStore) UpdateUserKeys(ctx context.Context, userID uuid.UUID, encryptedPrivKey, encryptedRecoveryKey, opaqueReg []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET encrypted_private_key = $2, encrypted_recovery_key = $3, opaque_registration = $4,
			recovery_version = 2
		 WHERE user_id = $1`,
		userID, encryptedPrivKey, encryptedRecoveryKey, opaqueReg,
	)
	if err != nil {
		return fmt.Errorf("update user keys: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// UpdateRecoveryOPAQUE updates the OPAQUE-based recovery data for a user.
func (s *AuthStore) UpdateRecoveryOPAQUE(ctx context.Context, userID uuid.UUID, opaqueRecoveryReg, recoveryBlob []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET opaque_recovery_registration = $2, recovery_blob = $3 WHERE user_id = $1`,
		userID, opaqueRecoveryReg, recoveryBlob,
	)
	if err != nil {
		return fmt.Errorf("update recovery opaque: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// UpdateUserPublicKeys replaces the user's public keys (email recovery key reset).
func (s *AuthStore) UpdateUserPublicKeys(ctx context.Context, userID uuid.UUID, pubKeyEncryption, pubKeySigning []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET public_key_encryption = $2, public_key_signing = $3
		 WHERE user_id = $1`,
		userID, pubKeyEncryption, pubKeySigning,
	)
	if err != nil {
		return fmt.Errorf("update user public keys: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// UpdateUserKEMKeys sets the ML-KEM-768 public and encrypted private keys for a user.
func (s *AuthStore) UpdateUserKEMKeys(ctx context.Context, userID uuid.UUID, pubKeyKEM, encPrivKeyKEM []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET public_key_kem = $2, encrypted_private_key_kem = $3
		 WHERE user_id = $1`,
		userID, pubKeyKEM, encPrivKeyKEM,
	)
	if err != nil {
		return fmt.Errorf("update user KEM keys: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// CreateSession inserts a new session into the sessions table.
func (s *AuthStore) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO sessions (session_id, user_id, created_at, expires_at, refresh_token_hash, token_hash)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		sess.SessionID, sess.UserID, sess.CreatedAt, sess.ExpiresAt, sess.RefreshTokenHash, sess.TokenHash,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by its ID if it has not expired.
func (s *AuthStore) GetSession(ctx context.Context, sessionID uuid.UUID) (*Session, error) {
	sess := &Session{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT session_id, user_id, created_at, expires_at, refresh_token_hash, COALESCE(token_hash, ''::bytea)
		 FROM sessions WHERE session_id = $1 AND expires_at > now()`, sessionID,
	).Scan(
		&sess.SessionID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RefreshTokenHash, &sess.TokenHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("session not found or expired: %s", sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return sess, nil
}

// GetSessionByTokenHash finds a non-expired session by the SHA-256 hash of its bearer token.
func (s *AuthStore) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	sess := &Session{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT session_id, user_id, created_at, expires_at, refresh_token_hash, token_hash
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHash,
	).Scan(
		&sess.SessionID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RefreshTokenHash, &sess.TokenHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("session not found or expired for token hash")
	}
	if err != nil {
		return nil, fmt.Errorf("get session by token hash: %w", err)
	}
	return sess, nil
}

// HashSessionToken returns a keyed hash of a session bearer token.
// F-01 fix: Uses HMAC-SHA256 with domain-separated context ("session:") to
// match the security level of refresh token hashing and prevent cross-purpose
// hash collisions. Falls back to plain SHA-256 in development.
func HashSessionToken(token []byte) []byte {
	if tokenHMACKey != nil {
		mac := hmac.New(sha256.New, tokenHMACKey)
		mac.Write([]byte("session:"))
		mac.Write(token)
		return mac.Sum(nil)
	}
	// Fallback for development when no HMAC key is configured.
	h := sha256.Sum256(token)
	return h[:]
}

// GetSessionByRefreshHash finds a non-expired session by its refresh token hash.
func (s *AuthStore) GetSessionByRefreshHash(ctx context.Context, refreshHash []byte) (*Session, error) {
	sess := &Session{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT session_id, user_id, created_at, expires_at, refresh_token_hash, COALESCE(token_hash, ''::bytea)
		 FROM sessions WHERE refresh_token_hash = $1 AND expires_at > now()`, refreshHash,
	).Scan(
		&sess.SessionID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RefreshTokenHash, &sess.TokenHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("session not found or expired for refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("get session by refresh hash: %w", err)
	}
	return sess, nil
}

// DeleteSession removes a session by its ID.
func (s *AuthStore) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM sessions WHERE session_id = $1`, sessionID,
	)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return nil
}

// UpdateSessionRefresh updates a session's expiry and refresh token hash atomically.
func (s *AuthStore) UpdateSessionRefresh(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time, newRefreshHash []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $2, refresh_token_hash = $3 WHERE session_id = $1`,
		sessionID, expiresAt, newRefreshHash,
	)
	if err != nil {
		return fmt.Errorf("update session refresh: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return nil
}

// UpdateSessionRefreshAndToken updates a session's expiry, refresh token hash, and bearer token hash atomically.
func (s *AuthStore) UpdateSessionRefreshAndToken(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time, newRefreshHash, newTokenHash []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $2, refresh_token_hash = $3, token_hash = $4 WHERE session_id = $1`,
		sessionID, expiresAt, newRefreshHash, newTokenHash,
	)
	if err != nil {
		return fmt.Errorf("update session refresh and token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return nil
}

// EnsureTenant gets or creates a tenant for the given domain, returning its ID.
func (s *AuthStore) EnsureTenant(ctx context.Context, domain string) (uuid.UUID, error) {
	var tenantID uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT tenant_id FROM tenants WHERE domain = $1`, domain,
	).Scan(&tenantID)
	if err == nil {
		return tenantID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("lookup tenant: %w", err)
	}

	// Tenant does not exist, create it.
	tenantID = uuid.New()
	_, err = s.DB.Pool.Exec(ctx,
		`INSERT INTO tenants (tenant_id, domain) VALUES ($1, $2) ON CONFLICT (domain) DO NOTHING`,
		tenantID, domain,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create tenant: %w", err)
	}

	// Re-fetch in case of race (ON CONFLICT DO NOTHING means our insert may not have happened).
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT tenant_id FROM tenants WHERE domain = $1`, domain,
	).Scan(&tenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("refetch tenant: %w", err)
	}
	return tenantID, nil
}

// ListUsersByTenant returns all users belonging to the given tenant.
func (s *AuthStore) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID) ([]*User, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch, created_at,
			COALESCE(pgp_public_key, ''), COALESCE(tier, 'mail'), storage_used_bytes,
			COALESCE(account_status, 'active'), payment_failed_at,
			public_key_kem
		 FROM users WHERE tenant_id = $1 ORDER BY created_at LIMIT 10000`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list users by tenant: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(
			&u.UserID, &u.TenantID, &u.Address,
			&u.PublicKeyEncryption, &u.PublicKeySigning,
			&u.EncryptedPrivateKey, &u.EncryptedRecoveryKey,
			&u.OpaqueRegistration, &u.KeyEpoch, &u.CreatedAt,
			&u.PGPPublicKey, &u.Tier, &u.StorageUsedBytes,
			&u.AccountStatus, &u.PaymentFailedAt,
			&u.PublicKeyKEM,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// DeleteUser deletes a user and all their sessions atomically.
func (s *AuthStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete sessions first (foreign key or just cleanup).
	_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}

	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE user_id = $1 AND tenant_id = (SELECT tenant_id FROM users WHERE user_id = $1)`, userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return tx.Commit(ctx)
}

// ListSessions returns all non-expired sessions for a user.
func (s *AuthStore) ListSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT session_id, user_id, created_at, expires_at, refresh_token_hash, COALESCE(token_hash, ''::bytea)
		 FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		sess := &Session{}
		if err := rows.Scan(
			&sess.SessionID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.RefreshTokenHash, &sess.TokenHash,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

// DeleteSessionsExcept deletes all sessions for a user except the given session ID.
func (s *AuthStore) DeleteSessionsExcept(ctx context.Context, userID, exceptSessionID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1 AND session_id != $2`,
		userID, exceptSessionID,
	)
	if err != nil {
		return fmt.Errorf("delete sessions except: %w", err)
	}
	return nil
}

// DeleteAllSessions deletes every session for a user (used during account recovery).
func (s *AuthStore) DeleteAllSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("delete all sessions: %w", err)
	}
	return nil
}

// PurgeExpiredSessions deletes all sessions whose expires_at is in the past.
// Returns the number of rows deleted.
func (s *AuthStore) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.DB.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// sessionCleanupLockID is a PostgreSQL advisory lock ID for distributed session cleanup.
const sessionCleanupLockID int64 = 0x626D61696C636C6E // "bmailcln"

// PurgeExpiredSessionsWithLock acquires a PostgreSQL transaction-scoped advisory
// lock before purging, ensuring only one instance runs cleanup at a time. If
// another instance holds the lock, returns (0, nil) immediately.
func (s *AuthStore) PurgeExpiredSessionsWithLock(ctx context.Context) (int64, error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var acquired bool
	err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", sessionCleanupLockID).Scan(&acquired)
	if err != nil {
		return 0, fmt.Errorf("try advisory lock: %w", err)
	}
	if !acquired {
		return 0, nil // another instance is handling cleanup
	}

	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UpdateUserTier sets the user's premium tier.
func (s *AuthStore) UpdateUserTier(ctx context.Context, userID uuid.UUID, tier string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET tier = $2 WHERE user_id = $1`,
		userID, tier,
	)
	if err != nil {
		return fmt.Errorf("update user tier: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// IsWelcomeDismissed returns true if the user has already seen (or
// explicitly skipped) the post-registration welcome / upgrade
// walkthrough. New users land with NULL → false → the frontend
// redirects them through /app/activate?welcome=1 on their next login.
// Migration 098 backfilled all pre-existing rows to now() so legacy
// accounts don't get unexpectedly redirected.
func (s *AuthStore) IsWelcomeDismissed(ctx context.Context, userID uuid.UUID) (bool, error) {
	var dismissed bool
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT welcome_dismissed_at IS NOT NULL FROM users WHERE user_id = $1`, userID,
	).Scan(&dismissed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("welcome_dismissed lookup: %w", err)
	}
	return dismissed, nil
}

// MarkWelcomeDismissed flips welcome_dismissed_at to now() for the
// given user. Idempotent — re-marking an already-dismissed account
// is a no-op (the WHERE clause filters out non-NULL rows).
func (s *AuthStore) MarkWelcomeDismissed(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET welcome_dismissed_at = now()
		 WHERE user_id = $1 AND welcome_dismissed_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("mark welcome dismissed: %w", err)
	}
	return nil
}

// validAccountStatuses is the whitelist of allowed account status values.
var validAccountStatuses = map[string]bool{
	"active":           true,
	"pending_payment":  true,
	"payment_failed":   true,
	"suspended":        true,
	"purge_pending":    true,
	"deletion_pending": true,
}

// UpdateAccountStatus sets a user's account status.
// Only known status values are accepted to prevent invalid state transitions.
func (s *AuthStore) UpdateAccountStatus(ctx context.Context, userID uuid.UUID, status string) error {
	if !validAccountStatuses[status] {
		return fmt.Errorf("invalid account status: %q", status)
	}
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = $2 WHERE user_id = $1`,
		userID, status)
	if err != nil {
		return fmt.Errorf("update account status: %w", err)
	}
	return nil
}

// SetPaymentFailedAt marks when a user's payment first failed.
func (s *AuthStore) SetPaymentFailedAt(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET payment_failed_at = now(), account_status = 'payment_failed'
		 WHERE user_id = $1 AND account_status = 'active'`,
		userID)
	return err
}

// SetUserStripeCustomerID stores the Stripe customer ID on a user.
func (s *AuthStore) SetUserStripeCustomerID(ctx context.Context, userID uuid.UUID, customerID string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET stripe_customer_id = $2 WHERE user_id = $1`,
		userID, customerID)
	return err
}

// SetUserStripeSubscriptionID stores the Stripe subscription ID on a user.
func (s *AuthStore) SetUserStripeSubscriptionID(ctx context.Context, userID uuid.UUID, subID string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET stripe_subscription_id = $2 WHERE user_id = $1`,
		userID, subID)
	return err
}

// GetUserAffiliateCode returns the cached affiliate code for a user, or
// the empty string if none has been cached yet. KLB Order/Reporter is
// the source of truth; this column is just a hot cache so Settings →
// Affiliate doesn't hit KLB on every page load.
func (s *AuthStore) GetUserAffiliateCode(ctx context.Context, userID uuid.UUID) (string, error) {
	var code string
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(affiliate_code, '') FROM users WHERE user_id = $1`,
		userID,
	).Scan(&code)
	return code, err
}

// SetUserAffiliateCode caches the user's affiliate code. Idempotent.
func (s *AuthStore) SetUserAffiliateCode(ctx context.Context, userID uuid.UUID, code string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET affiliate_code = $2 WHERE user_id = $1`,
		userID, code)
	return err
}

// GetUserByStripeCustomerID looks up a user by Stripe customer ID.
func (s *AuthStore) GetUserByStripeCustomerID(ctx context.Context, customerID string) (*User, error) {
	u := &User{}
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT user_id, tenant_id, address, public_key_encryption, public_key_signing,
			encrypted_private_key, encrypted_recovery_key, opaque_registration, key_epoch,
			recovery_version, created_at, COALESCE(pgp_public_key, ''), COALESCE(tier, 'mail'),
			storage_used_bytes, COALESCE(account_status, 'active'), payment_failed_at,
			stripe_customer_id, stripe_subscription_id,
			totp_secret_encrypted, totp_enabled, totp_backup_codes, deletion_requested_at,
			public_key_kem
		 FROM users WHERE stripe_customer_id = $1`, customerID,
	).Scan(
		&u.UserID, &u.TenantID, &u.Address,
		&u.PublicKeyEncryption, &u.PublicKeySigning,
		&u.EncryptedPrivateKey, &u.EncryptedRecoveryKey,
		&u.OpaqueRegistration, &u.KeyEpoch, &u.RecoveryVersion,
		&u.CreatedAt, &u.PGPPublicKey, &u.Tier,
		&u.StorageUsedBytes, &u.AccountStatus, &u.PaymentFailedAt,
		&u.StripeCustomerID, &u.StripeSubscriptionID,
		&u.TOTPSecretEncrypted, &u.TOTPEnabled, &u.TOTPBackupCodes, &u.DeletionRequestedAt,
		&u.PublicKeyKEM,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user not found for stripe customer: %s", customerID)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by stripe customer: %w", err)
	}
	return u, nil
}

// TransitionPaymentFailedAccounts moves accounts through the payment failure lifecycle:
// payment_failed > 30 days → suspended (stops receiving mail)
// suspended > 30 days → purge_pending (marked for deletion)
func (s *AuthStore) TransitionPaymentFailedAccounts(ctx context.Context) (suspended, purgePending int64, err error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'suspended'
		 WHERE account_status = 'payment_failed' AND payment_failed_at < now() - interval '30 days'`)
	if err != nil {
		return 0, 0, fmt.Errorf("transition to suspended: %w", err)
	}
	suspended = tag.RowsAffected()

	tag, err = s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'purge_pending'
		 WHERE account_status = 'suspended' AND payment_failed_at < now() - interval '60 days'`)
	if err != nil {
		return suspended, 0, fmt.Errorf("transition to purge_pending: %w", err)
	}
	purgePending = tag.RowsAffected()
	return suspended, purgePending, nil
}

// BumpLastActivity records that the user did something authenticated
// (login, fetch, send, etc.). Drives the dormancy → tombstone lifecycle.
// Throttled to once-per-hour at the DB level via the conditional update,
// so calling it on every request is cheap.
func (s *AuthStore) BumpLastActivity(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET last_activity_at = now()
		 WHERE user_id = $1
		   AND (last_activity_at IS NULL OR last_activity_at < now() - interval '1 hour')`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("bump last_activity_at: %w", err)
	}
	return nil
}

// LifecycleTransitioned describes a user that just moved into a
// new account_status. Returned by the Mark* helpers so the cleanup
// cron can send a one-shot notification email per transition.
type LifecycleTransitioned struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Address  string
}

func scanLifecycleRows(rows pgx.Rows) ([]LifecycleTransitioned, error) {
	defer rows.Close()
	var out []LifecycleTransitioned
	for rows.Next() {
		var u LifecycleTransitioned
		if err := rows.Scan(&u.UserID, &u.TenantID, &u.Address); err != nil {
			return nil, fmt.Errorf("scan lifecycle row: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserSearchResult is the slim shape returned by SearchUsersByAddress.
// Just enough to render the support-panel result list — full detail
// comes from a follow-up GetUserByID once a row is selected.
type UserSearchResult struct {
	UserID        uuid.UUID
	TenantID      uuid.UUID
	Address       string
	Tier          string
	AccountType   string
	AccountStatus string
}

// SearchUsersByAddress does a case-insensitive substring match on
// users.address, ordered by best match (prefix > contains) then
// alphabetically. limit clamped to [1, 50]; default 25. Returns an
// empty slice if q is shorter than 2 chars (we don't want every user
// in the panel for a one-character search).
func (s *AuthStore) SearchUsersByAddress(ctx context.Context, q string, limit int) ([]UserSearchResult, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) < 2 {
		return []UserSearchResult{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 25
	}
	// Escape LIKE wildcards in the user's input so 'foo%' doesn't
	// blow up the search to all addresses.
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT user_id, tenant_id, address,
		        COALESCE(tier, 'mail'),
		        COALESCE(account_type, 'primary'),
		        COALESCE(account_status, 'active')
		 FROM users
		 WHERE address ILIKE '%' || $1 || '%' ESCAPE '\'
		 ORDER BY CASE WHEN address ILIKE $1 || '%' ESCAPE '\' THEN 0 ELSE 1 END,
		          address
		 LIMIT $2`,
		escaped, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("search users: %w", err)
	}
	defer rows.Close()
	out := []UserSearchResult{}
	for rows.Next() {
		r := UserSearchResult{}
		if err := rows.Scan(&r.UserID, &r.TenantID, &r.Address, &r.Tier, &r.AccountType, &r.AccountStatus); err != nil {
			return nil, fmt.Errorf("scan search result: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DowngradeToFree forces a single user to tier=free + status=lapsed_to_free
// regardless of their current state. Used by the Stripe refund webhook
// when a full refund is issued — the customer paid, got their money back,
// and shouldn't keep paid features. Subscription cancellation is the
// caller's responsibility (separate Stripe API call).
func (s *AuthStore) DowngradeToFree(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET account_status = 'lapsed_to_free', tier = 'free'
		 WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("downgrade to free: %w", err)
	}
	return nil
}

// MarkLapsedToFree finds payment_failed accounts whose last failed
// charge is older than the cutoff and transitions them to
// lapsed_to_free + tier='free'. The data stays put; if the user is
// over the new 100 MB cap they end up in the over-cap soft-bounce
// path until they upgrade or clear space.
//
// Returns the rows that just transitioned so the caller can send
// notification emails.
func (s *AuthStore) MarkLapsedToFree(ctx context.Context, cutoff time.Time) ([]LifecycleTransitioned, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`UPDATE users
		 SET account_status = 'lapsed_to_free', tier = 'free'
		 WHERE account_status = 'payment_failed' AND payment_failed_at < $1
		 RETURNING user_id, tenant_id, address`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("mark lapsed_to_free: %w", err)
	}
	return scanLifecycleRows(rows)
}

// MarkDormantTombstone finds active tier='free' accounts inactive for
// longer than the cutoff and flips them to tombstone. The actual data
// wipe is handled by the PurgeUser pipeline (which preserves auth
// records when the new status is 'tombstone' so the rightful owner
// can come back via password / mnemonic / backup email).
//
// Returns the rows that just transitioned so the caller can send a
// "data was wiped, address still yours" notification email — note
// this is the post-fact email; the pre-emptive warning fires earlier
// via a separate query (see MarkDormantTombstoneCandidates).
func (s *AuthStore) MarkDormantTombstone(ctx context.Context, cutoff time.Time) ([]LifecycleTransitioned, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`UPDATE users
		 SET account_status = 'tombstone'
		 WHERE account_status = 'active'
		   AND tier = 'free'
		   AND COALESCE(last_activity_at, created_at) < $1
		 RETURNING user_id, tenant_id, address`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("mark dormant tombstone: %w", err)
	}
	return scanLifecycleRows(rows)
}

// MarkLapsedPruneWarned finds lapsed_to_free accounts that have been
// inactive for the full grace period and arms the 30-day pruning
// countdown. Returns the rows so the caller can send the
// "30 days until cleanup" notification.
func (s *AuthStore) MarkLapsedPruneWarned(ctx context.Context, cutoff time.Time) ([]LifecycleTransitioned, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`UPDATE users
		 SET account_status = 'prune_warned'
		 WHERE account_status = 'lapsed_to_free'
		   AND COALESCE(last_activity_at, created_at) < $1
		 RETURNING user_id, tenant_id, address`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("mark prune_warned: %w", err)
	}
	return scanLifecycleRows(rows)
}

// GetUsersByStatus returns up to `limit` users in the given status.
// Used by the pruning worker to find rows in 'pruning' state. Returns
// minimal columns — user_id, tenant_id, address, storage_used_bytes —
// since the worker only needs identification + over-cap detection.
func (s *AuthStore) GetUsersByStatus(ctx context.Context, status string, limit int) ([]User, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT user_id, tenant_id, address, storage_used_bytes
		 FROM users WHERE account_status = $1 LIMIT $2`,
		status, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list users by status: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if scanErr := rows.Scan(&u.UserID, &u.TenantID, &u.Address, &u.StorageUsedBytes); scanErr != nil {
			return nil, fmt.Errorf("scan user by status: %w", scanErr)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// BounceFreezeThreshold is the 7-day rolling permanent-bounce count
// at which an account is automatically frozen for sending. Read by
// the smtp-outbound enclave when a bounce fires; if IncrementBounces
// returns >= this value, the enclave calls FreezeForAbuse.
const BounceFreezeThreshold = 3

// IncrementBounces atomically bumps the user's recent_bounces counter
// by 1 and returns the new total. Reset to 0 weekly by the cleanup
// cron via ResetStaleBounceCounters.
func (s *AuthStore) IncrementBounces(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE users
		 SET recent_bounces = recent_bounces + 1
		 WHERE user_id = $1
		 RETURNING recent_bounces`,
		userID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("increment bounces: %w", err)
	}
	return n, nil
}

// ResetUserBounces zeroes a single user's recent_bounces counter and
// stamps the reset window. Used by the admin panel for support
// staff to manually clear an account's bounce history (e.g., after
// the user fixed their downstream issue).
func (s *AuthStore) ResetUserBounces(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET recent_bounces = 0, recent_bounces_reset_at = now() WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("reset user bounces: %w", err)
	}
	return nil
}

// ResetStaleBounceCounters resets recent_bounces to 0 for users whose
// recent_bounces_reset_at is older than the cutoff (typically now() -
// 7 days). Call from the cleanup cron weekly.
func (s *AuthStore) ResetStaleBounceCounters(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		 SET recent_bounces = 0, recent_bounces_reset_at = now()
		 WHERE recent_bounces_reset_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("reset bounce counters: %w", err)
	}
	return tag.RowsAffected(), nil
}

// FreezeForAbuse flips an active account into 'suspended' for abuse
// (bounce-rate threshold or spam complaint feedback). Read access
// remains, sending is blocked. Idempotent — re-running on an already-
// suspended row is a no-op.
func (s *AuthStore) FreezeForAbuse(ctx context.Context, userID uuid.UUID, reason string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'suspended'
		 WHERE user_id = $1 AND account_status = 'active'`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("freeze for abuse: %w", err)
	}
	slog.Warn("account frozen for abuse", "user_id", userID, "reason", reason)
	return nil
}

// ReactivateIfTombstoned flips a tombstoned/deleted_tombstone account
// back to 'active' on successful recovery (mnemonic, backup email).
// Resets last_activity_at to now() so the dormancy clock starts over.
// No-op for users in any other state — recovery preserves their
// current status (active stays active, payment_failed stays
// payment_failed, etc.).
//
// Called from the recovery handlers after the new keys + OPAQUE
// registration have been written. The user lands in a fresh empty
// mailbox at their original address.
func (s *AuthStore) ReactivateIfTombstoned(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users
		   SET account_status = 'active',
		       deletion_requested_at = NULL,
		       last_activity_at = now()
		 WHERE user_id = $1
		   AND account_status IN ('tombstone', 'deleted_tombstone')`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("reactivate from tombstone: %w", err)
	}
	return nil
}

// FinishPruning flips a user from 'pruning' back to 'active' once
// their storage is under the free-tier cap. Called by the pruning
// worker when a user's storage_used_bytes drops below 100 MB.
func (s *AuthStore) FinishPruning(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'active'
		 WHERE user_id = $1 AND account_status = 'pruning'`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("finish pruning: %w", err)
	}
	return nil
}

// MarkLapsedPruning advances prune_warned accounts past their final
// 30-day countdown into pruning. The pruning worker walks rows in
// this state and removes oldest mail until storage is under 100 MB.
// Returns the rows so the caller can send the "cleanup started" notice.
func (s *AuthStore) MarkLapsedPruning(ctx context.Context, cutoff time.Time) ([]LifecycleTransitioned, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`UPDATE users
		 SET account_status = 'pruning'
		 WHERE account_status = 'prune_warned'
		   AND COALESCE(last_activity_at, created_at) < $1
		 RETURNING user_id, tenant_id, address`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("mark pruning: %w", err)
	}
	return scanLifecycleRows(rows)
}

// MarkStalePendingPayment transitions stale pending_payment accounts to
// purge_pending so they get cleaned up by the PurgeUser pipeline.
func (s *AuthStore) MarkStalePendingPayment(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'purge_pending', deletion_requested_at = now()
		 WHERE account_status = 'pending_payment' AND created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("mark stale pending_payment: %w", err)
	}
	return tag.RowsAffected(), nil
}

// UpdatePGPPublicKey updates a user's PGP public key (armored).
func (s *AuthStore) UpdatePGPPublicKey(ctx context.Context, userID uuid.UUID, armoredKey string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET pgp_public_key = $1 WHERE user_id = $2`,
		armoredKey, userID,
	)
	if err != nil {
		return fmt.Errorf("update PGP public key: %w", err)
	}
	return nil
}

// GetPGPPublicKeyByAddress returns a user's PGP public key by email address.
// Returns "" if the user has no PGP key.
func (s *AuthStore) GetPGPPublicKeyByAddress(ctx context.Context, address string) (string, error) {
	var key string
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(pgp_public_key, '') FROM users WHERE address = $1`, address,
	).Scan(&key)
	if err != nil {
		return "", fmt.Errorf("get PGP key for %s: %w", address, err)
	}
	return key, nil
}

// RequireTokenHMACKey panics if running in production without an HMAC key.
// Call this at startup to fail fast rather than silently falling back to plain SHA-256.
func RequireTokenHMACKey() {
	if os.Getenv("VP_ENV") == "production" && tokenHMACKey == nil {
		log.Fatal("FATAL: token HMAC key not initialized in production")
	}
}

// RequireRefreshTokenKey is an alias for RequireTokenHMACKey for backward compatibility.
func RequireRefreshTokenKey() {
	RequireTokenHMACKey()
}

// GetUserSettings returns the encrypted signature and display name for a user.
func (s *AuthStore) GetUserSettings(ctx context.Context, userID uuid.UUID) (signature, displayName string, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT signature, display_name FROM user_settings WHERE user_id = $1`, userID,
	).Scan(&signature, &displayName)
	if err != nil {
		return "", "", fmt.Errorf("get user settings: %w", err)
	}
	return signature, displayName, nil
}

// UpsertUserSettings creates or updates encrypted user settings.
func (s *AuthStore) UpsertUserSettings(ctx context.Context, userID uuid.UUID, signature, displayName *string) error {
	// Use COALESCE to preserve existing values when a field is nil.
	// EXCLUDED refers to the values from the INSERT that triggered the conflict.
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO user_settings (user_id, signature, display_name)
		 VALUES ($1, COALESCE($2, ''), COALESCE($3, ''))
		 ON CONFLICT (user_id) DO UPDATE SET
		   signature = COALESCE($2, user_settings.signature),
		   display_name = COALESCE($3, user_settings.display_name),
		   updated_at = now()`,
		userID, signature, displayName,
	)
	if err != nil {
		return fmt.Errorf("upsert user settings: %w", err)
	}
	return nil
}

// SetTOTPSecret stores the TEE-sealed TOTP secret on a user.
// Called during TOTP setup before confirmation.
func (s *AuthStore) SetTOTPSecret(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET totp_secret_encrypted = $2 WHERE user_id = $1`,
		userID, encryptedSecret,
	)
	if err != nil {
		return fmt.Errorf("set totp secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// EnableTOTP sets totp_enabled=true and stores the bcrypt-hashed backup codes.
func (s *AuthStore) EnableTOTP(ctx context.Context, userID uuid.UUID, backupCodesHash string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET totp_enabled = true, totp_backup_codes = $2 WHERE user_id = $1`,
		userID, backupCodesHash,
	)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// DisableTOTP sets totp_enabled=false and clears the secret and backup codes.
func (s *AuthStore) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET totp_enabled = false, totp_secret_encrypted = NULL, totp_backup_codes = NULL WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// UseTOTPBackupCode updates the backup codes after one has been consumed.
func (s *AuthStore) UseTOTPBackupCode(ctx context.Context, userID uuid.UUID, newCodes string) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET totp_backup_codes = $2 WHERE user_id = $1`,
		userID, newCodes,
	)
	if err != nil {
		return fmt.Errorf("use totp backup code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// --- Account Deletion ---

// RequestDeletion marks an account for deletion with a 30-day grace
// period. Sets account_status='deleted_tombstone' and
// deletion_requested_at=now(). After 30 days the cleanup cron calls
// TombstoneUser to wipe data while preserving the address (which can
// never return to the signup pool — see the lifecycle plan).
func (s *AuthStore) RequestDeletion(ctx context.Context, userID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'deleted_tombstone', deletion_requested_at = now()
		 WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("request deletion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// CancelDeletion reverses a pending deletion, restoring the account to
// active. Accepts both the new 'deleted_tombstone' state and the
// legacy 'deletion_pending' for back-compat.
func (s *AuthStore) CancelDeletion(ctx context.Context, userID uuid.UUID) error {
	tag, err := s.DB.Pool.Exec(ctx,
		`UPDATE users SET account_status = 'active', deletion_requested_at = NULL
		 WHERE user_id = $1
		   AND account_status IN ('deleted_tombstone', 'deletion_pending')`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("cancel deletion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found or not pending deletion: %s", userID)
	}
	return nil
}

// GetDeletionPendingUsers returns users ready for data wipe via
// TombstoneUser / PurgeUser. The cleanup worker calls this periodically.
//
// Routes:
//   - 'tombstone'         — lifecycle dormancy hit; wipe immediately
//                           (the lifecycle cron only flips to this
//                           after 365d of inactivity + warnings).
//   - 'deleted_tombstone' — user-initiated delete, 30d grace from
//                           deletion_requested_at then wipe.
//   - 'deletion_pending'  — legacy alias of deleted_tombstone, 14d
//                           grace (kept for back-compat).
//   - 'purge_pending'     — legacy stale-pending_payment sweep.
func (s *AuthStore) GetDeletionPendingUsers(ctx context.Context, olderThan time.Time) ([]User, error) {
	rows, err := s.DB.Pool.Query(ctx,
		`SELECT user_id, tenant_id, address, account_status, deletion_requested_at
		 FROM users
		 WHERE account_status = 'tombstone'
		    OR (account_status IN ('deleted_tombstone', 'deletion_pending', 'purge_pending')
		        AND (deletion_requested_at IS NULL OR deletion_requested_at < $1))
		 LIMIT 1000`, olderThan,
	)
	if err != nil {
		return nil, fmt.Errorf("get deletion pending users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UserID, &u.TenantID, &u.Address, &u.AccountStatus, &u.DeletionRequestedAt); err != nil {
			return nil, fmt.Errorf("scan deletion pending user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deletion pending users: %w", err)
	}
	return users, nil
}

// PurgeUser permanently deletes a user and all their data in a single transaction.
// Deletes messages, folders, sessions, and then the user row (CASCADE handles
// contacts, tokens, labels, rules, settings, etc.).
func (s *AuthStore) PurgeUser(ctx context.Context, userID, tenantID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin purge tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete messages first (may have blob_ref references).
	_, err = tx.Exec(ctx, `DELETE FROM messages WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete messages: %w", err)
	}

	// Delete folders.
	_, err = tx.Exec(ctx, `DELETE FROM folders WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete folders: %w", err)
	}

	// Delete sessions (sessions table may not have tenant_id; scope by user_id).
	_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}

	// Delete user row — enforce tenant_id match as defense-in-depth (M9).
	// CASCADE handles contacts, api_tokens, labels, rules,
	// user_settings, blocked_senders, push_subscriptions, etc.
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}

	return tx.Commit(ctx)
}

// TombstoneUser wipes all user data while preserving the row + auth
// records, so the address never returns to the signup pool but the
// rightful owner can reclaim it via password / mnemonic / backup
// email through the recovery flow. Called by the cleanup worker for
// rows in 'tombstone' (lifecycle dormancy) or 'deleted_tombstone'
// (user-initiated delete after 30d grace) state.
//
// Wiped:    messages, folders (+ blob refs), sessions, public keys,
//           encrypted private keys, KEM keys, PGP key, TOTP secrets,
//           Stripe identifiers, payment_failed_at, storage counters,
//           fakeid sentinels. CASCADE handles attachments, contacts,
//           api_tokens, labels, rules, blocked_senders,
//           push_subscriptions, calendar/drive rows the user owned.
//
// Preserved: user_id, tenant_id, address, account_status,
//            tombstoned_at (created_at retained), opaque_registration
//            (password login), opaque_recovery_registration (mnemonic
//            login), recovery_blob, key_epoch, account_type. Backup
//            email lives on user_settings and is retained too.
//
// Idempotent: re-running on an already-tombstoned row is a no-op.
func (s *AuthStore) TombstoneUser(ctx context.Context, userID, tenantID uuid.UUID) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tombstone tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Wipe owned data tables. Split into two groups by parameter
	// count to keep the SQL straightforward — tenant-scoped tables
	// take both userID + tenantID (defense-in-depth scoping); the
	// rest take only userID.
	tenantScoped := []string{
		`DELETE FROM messages WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM folders  WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM contacts WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM contact_groups WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM labels   WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM mail_rules WHERE user_id = $1 AND tenant_id = $2`,
		`DELETE FROM blocked_senders WHERE user_id = $1 AND tenant_id = $2`,
	}
	userScoped := []string{
		`DELETE FROM api_tokens WHERE user_id = $1`,
		`DELETE FROM push_subscriptions WHERE user_id = $1`,
		`DELETE FROM webhooks WHERE user_id = $1`,
		`DELETE FROM pending_sends WHERE user_id = $1`,
		`DELETE FROM sessions WHERE user_id = $1`,
	}
	for _, q := range tenantScoped {
		if _, err := tx.Exec(ctx, q, userID, tenantID); err != nil {
			// Some of these tables may not exist on every deployment
			// (e.g. webhooks isn't enabled in product). Treat
			// missing-relation errors as soft and continue.
			if !isUndefinedTable(err) {
				return fmt.Errorf("tombstone wipe (%s): %w", q, err)
			}
		}
	}
	for _, q := range userScoped {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			if !isUndefinedTable(err) {
				return fmt.Errorf("tombstone wipe (%s): %w", q, err)
			}
		}
	}

	// Wipe key material + identifiers on the user row. Preserve auth
	// records (opaque_registration, opaque_recovery_registration,
	// recovery_blob) so the rightful owner can come back. Set status
	// to whichever tombstone variant the row is already in (handled
	// by GetDeletionPendingUsers callers; we leave account_status
	// alone here so a row in 'deleted_tombstone' doesn't get re-
	// mapped to 'tombstone' or vice versa).
	_, err = tx.Exec(ctx, `
		UPDATE users SET
			public_key_encryption    = ''::bytea,
			public_key_signing       = ''::bytea,
			encrypted_private_key    = ''::bytea,
			encrypted_recovery_key   = ''::bytea,
			public_key_kem           = ''::bytea,
			encrypted_private_key_kem = ''::bytea,
			pgp_public_key           = NULL,
			totp_secret_encrypted    = NULL,
			totp_enabled             = false,
			totp_backup_codes        = NULL,
			stripe_customer_id       = NULL,
			stripe_subscription_id   = NULL,
			payment_failed_at        = NULL,
			storage_used_bytes       = 0,
			storage_blocks           = 0,
			has_fakeid               = false,
			fakeid_minted_at         = NULL,
			fakeid_allowed_release_at = NULL,
			tier                     = 'free'
		WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("tombstone user row: %w", err)
	}

	return tx.Commit(ctx)
}

// isUndefinedTable returns true when the error is "relation does not
// exist" — used by TombstoneUser to skip optional tables (webhooks,
// push_subscriptions, etc.) on deployments where they aren't
// installed.
func isUndefinedTable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "does not exist") &&
		(strings.Contains(msg, "relation") || strings.Contains(msg, "table"))
}

// --- Backup Email ---

// GetBackupEmail returns the backup email and its verification status for a user.
func (s *AuthStore) GetBackupEmail(ctx context.Context, userID uuid.UUID) (email string, verified bool, err error) {
	err = s.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(backup_email, ''), COALESCE(backup_email_verified, false)
		 FROM user_settings WHERE user_id = $1`, userID,
	).Scan(&email, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil // No settings row yet.
	}
	if err != nil {
		return "", false, fmt.Errorf("get backup email: %w", err)
	}
	return email, verified, nil
}

// SetBackupEmail stores a new backup email with a verification token.
// Resets verification status to false and sets a 24-hour token expiry.
func (s *AuthStore) SetBackupEmail(ctx context.Context, userID uuid.UUID, email, token string) error {
	_, err := s.DB.Pool.Exec(ctx,
		`INSERT INTO user_settings (user_id, backup_email, backup_email_verified, backup_email_token, backup_email_token_expires)
		 VALUES ($1, $2, false, $3, now() + interval '24 hours')
		 ON CONFLICT (user_id) DO UPDATE SET
			backup_email = $2,
			backup_email_verified = false,
			backup_email_token = $3,
			backup_email_token_expires = now() + interval '24 hours',
			updated_at = now()`,
		userID, email, token,
	)
	if err != nil {
		return fmt.Errorf("set backup email: %w", err)
	}
	return nil
}

// VerifyBackupEmail verifies a backup email by matching the token.
// Returns the user ID if successful.
func (s *AuthStore) VerifyBackupEmail(ctx context.Context, token string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`UPDATE user_settings
		 SET backup_email_verified = true, backup_email_token = NULL, backup_email_token_expires = NULL, updated_at = now()
		 WHERE backup_email_token = $1 AND backup_email_token_expires > now()
		 RETURNING user_id`, token,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("invalid or expired verification token")
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("verify backup email: %w", err)
	}
	return userID, nil
}

// GetUserByVerifiedBackupEmail looks up a user by their verified backup email address.
// Used for password recovery via backup email.
func (s *AuthStore) GetUserByVerifiedBackupEmail(ctx context.Context, address string) (*User, error) {
	var userID uuid.UUID
	err := s.DB.Pool.QueryRow(ctx,
		`SELECT us.user_id FROM user_settings us
		 JOIN users u ON u.user_id = us.user_id
		 WHERE u.address = $1 AND us.backup_email_verified = true AND us.backup_email IS NOT NULL AND us.backup_email != ''`,
		address,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no verified backup email for: %s", address)
	}
	if err != nil {
		return nil, fmt.Errorf("get user by verified backup email: %w", err)
	}
	return s.GetUserByID(ctx, userID)
}

// HashRefreshToken returns a keyed hash of a refresh token. Uses HMAC-SHA256
// with domain-separated context ("refresh:") if key is initialized, otherwise
// falls back to plain SHA-256 in development.
// F-01 fix: Added "refresh:" domain separation to prevent cross-purpose collisions.
func HashRefreshToken(token []byte) []byte {
	if tokenHMACKey != nil {
		mac := hmac.New(sha256.New, tokenHMACKey)
		mac.Write([]byte("refresh:"))
		mac.Write(token)
		return mac.Sum(nil)
	}
	// Fallback for development when no HMAC key is configured.
	h := sha256.Sum256(token)
	return h[:]
}
