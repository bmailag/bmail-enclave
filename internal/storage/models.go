package storage

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User represents a row in the users table.
type User struct {
	UserID                uuid.UUID `db:"user_id"`
	TenantID              uuid.UUID `db:"tenant_id"`
	Address               string    `db:"address"`
	PublicKeyEncryption   []byte    `db:"public_key_encryption"`
	PublicKeySigning      []byte    `db:"public_key_signing"`
	EncryptedPrivateKey   []byte    `db:"encrypted_private_key"`
	EncryptedRecoveryKey  []byte    `db:"encrypted_recovery_key"`
	OpaqueRegistration    []byte    `db:"opaque_registration"`
	KeyEpoch              int       `db:"key_epoch"`
	RecoveryVersion       int       `db:"recovery_version"` // 1 = legacy BIP-39→AES, 2 = HKDF-derived
	CreatedAt             time.Time `db:"created_at"`
	LastActivityAt        time.Time `db:"last_activity_at"` // updated on any authenticated request; drives dormancy → tombstone transition
	PGPPublicKey          string    `db:"pgp_public_key"`      // armored OpenPGP public key for WKD
	Tier                  string     `db:"tier"`                // "mail", "unlimited", "business", "enterprise"
	StorageUsedBytes      int64      `db:"storage_used_bytes"`
	AccountStatus         string     `db:"account_status"`      // pending_payment, active, payment_failed, suspended, purge_pending
	PaymentFailedAt       *time.Time `db:"payment_failed_at"`
	StripeCustomerID      *string    `db:"stripe_customer_id"`
	StripeSubscriptionID  *string    `db:"stripe_subscription_id"`
	TOTPSecretEncrypted   []byte     `db:"totp_secret_encrypted"`
	TOTPEnabled           bool       `db:"totp_enabled"`
	TOTPBackupCodes       *string    `db:"totp_backup_codes"`
	DeletionRequestedAt        *time.Time `db:"deletion_requested_at"`
	OpaqueRecoveryRegistration []byte     `db:"opaque_recovery_registration"` // OPAQUE record for mnemonic-based ZK recovery
	RecoveryBlob               []byte     `db:"recovery_blob"`                // private key encrypted with mnemonic OPAQUE export key
	PublicKeyKEM               []byte     `db:"public_key_kem"`               // ML-KEM-768 encapsulation key (1184 bytes), nil if not registered
	EncryptedPrivateKeyKEM     []byte     `db:"encrypted_private_key_kem"`    // ML-KEM-768 decapsulation key seed encrypted under OPAQUE export key
	// Fake ID columns. NULL for primary accounts; NOT NULL (enforced at app
	// layer) for fakeid accounts. See migration 085_fakeid_columns.up.sql.
	AccountType        string     `db:"account_type"`          // 'primary' or 'fakeid'
	DormancyWindowDays *int       `db:"dormancy_window_days"`  // 30 / 90 / 180 / 365
	ValidUntil         *time.Time `db:"valid_until"`           // current expiry, advanced on login
	MaxValidUntil      *time.Time `db:"max_valid_until"`       // ceiling set at mint, advanced via ratchet

	// Primary-side Fake ID ownership tracking (migrations 087, 088). Only
	// relevant on account_type='primary' rows. Enforces strict 1-per-primary:
	// claim is atomic at mint, release is bounded by fakeid_allowed_release_at
	// (the hard max lifetime of the issued Fake ID), and a worker sweep
	// auto-clears has_fakeid once the deadline passes.
	HasFakeID              bool       `db:"has_fakeid"`
	FakeIDMintedAt         *time.Time `db:"fakeid_minted_at"`
	FakeIDAllowedReleaseAt *time.Time `db:"fakeid_allowed_release_at"` // migration 088

	// migration 090: sentinel flipped to TRUE once the Phase 2e
	// backfill has seeded this primary into fakeid_consumed_slots on
	// the enclave side. Not read outside the backfill. Dropped in
	// Phase 5 alongside HasFakeID et al.
	FakeIDMigrated bool `db:"fakeid_migrated"`

	// migration 091: per-user storage top-up count, mirrored from the
	// Stripe subscription's STRIPE_PRICE_STORAGE line item quantity.
	// Each block = 10 GB. EffectiveStorageLimit adds storage_blocks *
	// 10 GB to the base 15 GB for primaries.
	StorageBlocks int `db:"storage_blocks"`
}

// Session represents a row in the sessions table.
type Session struct {
	SessionID        uuid.UUID `db:"session_id"`
	UserID           uuid.UUID `db:"user_id"`
	CreatedAt        time.Time `db:"created_at"`
	ExpiresAt        time.Time `db:"expires_at"`
	RefreshTokenHash []byte    `db:"refresh_token_hash"`
	TokenHash        []byte    `db:"token_hash"`
}

// Tenant represents a row in the tenants table.
type Tenant struct {
	TenantID                uuid.UUID  `db:"tenant_id"`
	Domain                  string     `db:"domain"`
	CreatedAt               time.Time  `db:"created_at"`
	MXVerified              bool       `db:"mx_verified"`
	DKIMPrivateKeyEncrypted    []byte     `db:"dkim_private_key_encrypted"` // Ed25519 sealed seed
	DKIMPublicKey              string     `db:"dkim_public_key"`
	DKIMSelector               string     `db:"dkim_selector"`
	DKIMRSAPrivateKeyEncrypted []byte     `db:"dkim_rsa_private_key_encrypted"` // RSA PKCS8 sealed
	DKIMRSAPublicKey           string     `db:"dkim_rsa_public_key"`
	DKIMRSASelector            string     `db:"dkim_rsa_selector"`
	Tier                       string     `db:"tier"`          // mail, unlimited, business, enterprise
	OwnerUserID                *uuid.UUID `db:"owner_user_id"` // nil for platform-managed default domains
	Verified                   bool       `db:"verified"`      // domain ownership verified
	MailboxLimit               int        `db:"mailbox_limit"`
	ExtraStorageBlocks         int        `db:"extra_storage_blocks"`
	StripeCustomerID           *string    `db:"stripe_customer_id"`
	StripeSubscriptionID       *string    `db:"stripe_subscription_id"`

	// DKIMPoolSelector — when non-empty, smtp-outbound signs mail for
	// this tenant with the pool DKIM key fetched from keystore role
	// smtp-outbound-dkim-pool-<selector>. Empty means legacy per-tenant
	// keys (DKIM*PrivateKeyEncrypted) are authoritative. Per ADR-007.
	DKIMPoolSelector string `db:"dkim_pool_selector"`
}

// DomainVerification represents a row in the domain_verifications table.
type DomainVerification struct {
	VerificationID uuid.UUID  `db:"verification_id"`
	TenantID       uuid.UUID  `db:"tenant_id"`
	Domain         string     `db:"domain"`
	ChallengeToken string     `db:"challenge_token"`
	Status         string     `db:"status"` // pending, verified, expired
	CreatedAt      time.Time  `db:"created_at"`
	VerifiedAt     *time.Time `db:"verified_at"`
	ExpiresAt      time.Time  `db:"expires_at"`
}

// TenantRole represents a row in the tenant_roles table.
type TenantRole struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	TenantID  uuid.UUID `db:"tenant_id"`
	Role      string    `db:"role"` // owner, admin, member
	CreatedAt time.Time `db:"created_at"`
}

// TierLimits represents a row in the tier_limits table.
type TierLimits struct {
	Tier             string `db:"tier"`
	MaxMailboxes     int    `db:"max_mailboxes"`     // -1 = unlimited
	MaxStorageBytes  int64  `db:"max_storage_bytes"`
	MaxCustomDomains int    `db:"max_custom_domains"`
	PriceCents       int    `db:"price_cents"`
}

// BillingCredit represents a row in the billing_credits table.
type BillingCredit struct {
	CreditID     uuid.UUID `db:"credit_id"`
	TenantID     uuid.UUID `db:"tenant_id"`
	Tier         string    `db:"tier"`
	MailboxQuota int       `db:"mailbox_quota"`
	ValidFrom    time.Time `db:"valid_from"`
	ValidUntil   time.Time `db:"valid_until"`
	TokenHash      []byte    `db:"token_hash"`
	PriceCentsEach int       `db:"price_cents_each"`
	CreatedAt      time.Time `db:"created_at"`
}

// PricingBracket defines per-mailbox pricing for a volume range.
type PricingBracket struct {
	MinMailboxes int `db:"min_mailboxes"`
	MaxMailboxes int `db:"max_mailboxes"`
	PriceCents   int `db:"price_cents"`
}

// StorageAddon tracks purchased extra storage blocks for a tenant.
type StorageAddon struct {
	AddonID    uuid.UUID `db:"addon_id"`
	TenantID   uuid.UUID `db:"tenant_id"`
	Blocks     int       `db:"blocks"`
	PriceCents int       `db:"price_cents"`
	ValidFrom  time.Time `db:"valid_from"`
	ValidUntil time.Time `db:"valid_until"`
	CreatedAt  time.Time `db:"created_at"`
}

// DomainInvitation represents a row in the domain_invitations table.
type DomainInvitation struct {
	InvitationID uuid.UUID `db:"invitation_id"`
	TenantID     uuid.UUID `db:"tenant_id"`
	Address      string    `db:"address"`
	InviteToken  string    `db:"invite_token"`
	CreatedBy    uuid.UUID `db:"created_by"`
	Status       string    `db:"status"` // pending, accepted, expired
	CreatedAt    time.Time `db:"created_at"`
	ExpiresAt    time.Time `db:"expires_at"`
}

// Message represents a row in the messages table.
type Message struct {
	MessageID           uuid.UUID  `db:"message_id"`
	UserID              uuid.UUID  `db:"user_id"`
	TenantID            uuid.UUID  `db:"tenant_id"`
	FolderID            uuid.UUID  `db:"folder_id"`
	BlobRef             string     `db:"blob_ref"`
	EncryptedSubject    []byte     `db:"encrypted_subject"`
	EncryptedMessageKey []byte     `db:"encrypted_message_key"`
	EphemeralPubkey     []byte     `db:"ephemeral_pubkey"`
	// Phase B3: full RFC 5322 headers JSON encrypted with the SAME
	// message key as the body/subject (AAD "headers"). Carries
	// display names. The per-field bare envelope columns from B1/B2
	// were dropped by migration 070 — encrypted_headers replaces
	// them. The blind index stays for SGX block-list / auto-add
	// lookups that need to match a sender without decryption.
	SenderBlindIndex    string     `db:"sender_blind_index"`
	EncryptedHeaders    []byte     `db:"encrypted_headers"`
	ReceivedAt          time.Time  `db:"received_at"`
	SizeBytes           int64      `db:"size_bytes"`
	HasAttachments      bool       `db:"has_attachments"`
	IsRead              bool       `db:"is_read"`
	KeyEpoch            int        `db:"key_epoch"`
	EnclaveReceipt      []byte     `db:"enclave_receipt"`
	InReplyTo           *string    `db:"in_reply_to"`
	References          *string    `db:"references"`
	ThreadID            *uuid.UUID `db:"thread_id"`
	EncryptionType      string     `db:"encryption_type"` // "bmail", "pgp", "smime", "plaintext", "received"
	IsStarred           bool       `db:"is_starred"`
	Subject             *string    `db:"subject"`        // plaintext subject for non-E2E messages (received); NULL for E2E
	RFCMessageID        *string    `db:"rfc_message_id"` // RFC 5322 Message-ID header (for threading via In-Reply-To)
	RawBlobRef          *string    `db:"raw_blob_ref"`          // encrypted original RFC 5322 message (inbound only)
	RawBlobFormat       string     `db:"raw_blob_format"`       // encryption format: "XChaCha20-Poly1305" or "XChaCha20-Poly1305-Chunked(65536)"
	EncryptedRawMeta    []byte     `db:"encrypted_raw_meta"`    // encrypted MIME structure metadata (headers + byte offsets)
}

// Label represents a row in the labels table.
type Label struct {
	LabelID       uuid.UUID `db:"label_id"`
	UserID        uuid.UUID `db:"user_id"`
	TenantID      uuid.UUID `db:"tenant_id"`
	NameEncrypted []byte    `db:"name_encrypted"`
	Color         string    `db:"color"`
	SortOrder     int       `db:"sort_order"`
	CreatedAt     time.Time `db:"created_at"`
}

// PendingSend represents a row in the pending_sends table.
type PendingSend struct {
	PendingID   uuid.UUID `db:"pending_id"`
	UserID      uuid.UUID `db:"user_id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	SendPayload []byte    `db:"send_payload"`
	SendAt      time.Time `db:"send_at"`
	Cancelled   bool      `db:"cancelled"`
	IsScheduled bool      `db:"is_scheduled"`
	CreatedAt   time.Time `db:"created_at"`
}

// MailRule represents a row in the mail_rules table.
type MailRule struct {
	RuleID              uuid.UUID `db:"rule_id"`
	UserID              uuid.UUID `db:"user_id"`
	TenantID            uuid.UUID `db:"tenant_id"`
	NameEncrypted       []byte    `db:"name_encrypted"`
	ConditionsEncrypted []byte    `db:"conditions_encrypted"`
	ActionsEncrypted    []byte    `db:"actions_encrypted"`
	Enabled             bool      `db:"enabled"`
	Priority            int       `db:"priority"`
	CreatedAt           time.Time `db:"created_at"`
}

// AutoReplySettings represents a row in the auto_reply_settings table.
type AutoReplySettings struct {
	UserID    uuid.UUID  `db:"user_id"`
	TenantID  uuid.UUID  `db:"tenant_id"`
	Enabled   bool       `db:"enabled"`
	Subject   string     `db:"subject"`
	Body      string     `db:"body"`
	StartDate *time.Time `db:"start_date"`
	EndDate   *time.Time `db:"end_date"`
	UpdatedAt time.Time  `db:"updated_at"`
}

// BlockedSender represents a row in the blocked_senders table.
type BlockedSender struct {
	ID                uuid.UUID `db:"id"`
	UserID            uuid.UUID `db:"user_id"`
	TenantID          uuid.UUID `db:"tenant_id"`
	SenderAddress     string    `db:"sender_address"` // legacy plaintext (transitional)
	SenderEncrypted   []byte    `db:"sender_encrypted"`
	SenderEphemeral   []byte    `db:"sender_ephemeral"`
	SenderEncKey      []byte    `db:"sender_enc_key"`
	SenderBlindIndex  string    `db:"sender_blind_index"`
	CreatedAt         time.Time `db:"created_at"`
}

// PushSubscription represents a row in the push_subscriptions table.
type PushSubscription struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	TenantID  uuid.UUID `db:"tenant_id"`
	Platform  string    `db:"platform"` // "fcm" or "webpush"
	Endpoint  string    `db:"endpoint"` // FCM token or Web Push endpoint URL
	P256DH    string    `db:"p256dh"`   // Web Push only
	AuthKey   string    `db:"auth_key"` // Web Push only
	CreatedAt time.Time `db:"created_at"`
}

// AppleSubscription represents a row in the apple_subscriptions table.
type AppleSubscription struct {
	OriginalTransactionID string          `db:"original_transaction_id"`
	UserID                uuid.UUID       `db:"user_id"`
	TenantID              uuid.UUID       `db:"tenant_id"`
	ProductID             string          `db:"product_id"`
	PlanID                string          `db:"plan_id"`
	Status                string          `db:"status"` // active, expired, billing_retry, revoked
	PurchaseDate          time.Time       `db:"purchase_date"`
	ExpiresDate           *time.Time      `db:"expires_date"`
	LastTransactionID     string          `db:"last_transaction_id"`
	RenewalInfo           json.RawMessage `db:"renewal_info"`
	Environment           string          `db:"environment"` // Production, Sandbox
	CreatedAt             time.Time       `db:"created_at"`
	UpdatedAt             time.Time       `db:"updated_at"`
}

// GoogleSubscription represents a row in the google_subscriptions table.
type GoogleSubscription struct {
	PurchaseToken string     `db:"purchase_token"`
	UserID        uuid.UUID  `db:"user_id"`
	TenantID      uuid.UUID  `db:"tenant_id"`
	ProductID     string     `db:"product_id"`
	PlanID        string     `db:"plan_id"`
	Status        string     `db:"status"` // active, expired, on_hold, revoked, canceled
	PurchaseDate  time.Time  `db:"purchase_date"`
	ExpiresDate   *time.Time `db:"expires_date"`
	AutoRenewing  bool       `db:"auto_renewing"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
}

// Folder represents a row in the folders table.
type Folder struct {
	FolderID      uuid.UUID  `db:"folder_id"`
	UserID        uuid.UUID  `db:"user_id"`
	TenantID      uuid.UUID  `db:"tenant_id"`
	NameEncrypted []byte     `db:"name_encrypted"`
	FolderType    string     `db:"folder_type"`
	SortOrder     int        `db:"sort_order"`
	ParentID      *uuid.UUID `db:"parent_id"`
}
