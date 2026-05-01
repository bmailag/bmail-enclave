// Package keystore implements the bmail Keystore enclave (ADR-006).
//
// The keystore is a small, never-changing SGX enclave that holds long-lived
// secrets — TLS keys, DKIM keys, blind-sig keys — on behalf of the consumer
// enclaves (gateway, smtp-inbound, smtp-outbound, payment). Consumers
// authenticate via attested mTLS (MRENCLAVE-pinned, per-role allowlist) and
// fetch keys at startup. They never seal long-lived material themselves.
//
// Why: an operator with the EGo signing key can re-sign a malicious enclave
// with the same MRSIGNER, run it on a bmail host, and unseal any
// MRSIGNER-sealed disk file (today's gateway/smtp-*/payment all do this).
// That gives offline access to TLS keys, DKIM keys, blind-sig keys —
// enough to forge mail or Fake IDs without the running enclave's
// cooperation. The keystore closes that gap by sealing under MRENCLAVE
// (`SealUnique`) — only the exact published keystore code can unseal,
// and a malicious enclave with a different MRENCLAVE simply cannot.
//
// Trust model:
//   - **Two roots, one offline**: the EGo `private.pem` still signs all
//     enclaves (operational gate). The keystore's MRENCLAVE is a NEW root
//     of trust, published, audited, fixed.
//   - **Per-role MRENCLAVE allowlists**: gateway-tls is fetchable only by
//     gateway's specific MRENCLAVE; payment-blindsig-* only by payment's.
//     Compromising one consumer doesn't yield other roles' keys.
//   - **Chained delegation**: routine consumer updates use the running
//     consumer to delegate the next MRENCLAVE — operator can't unilaterally
//     add to the allowlist without an existing allowlisted enclave.
//   - **Operator break-glass**: an offline-stored Ed25519 credential can
//     bypass the chained-delegation check for disaster recovery. Same
//     custody profile as `private.pem.backup` today.
package keystore

import "time"

// Role identifies a key's purpose. The full role string scopes the
// allowlist: only MRENCLAVEs explicitly granted access to a role can
// fetch its key. Roles are flat namespaced strings, not enums, because
// per-domain DKIM / per-tier payment keys multiply combinatorially and a
// hardcoded enum would force the keystore to release every time.
//
// Reserved prefixes:
//
//	gateway-tls               — gateway's TLS private key
//	smtp-inbound-tls          — smtp-inbound's TLS private key (DANE-pinned)
//	smtp-outbound-dkim-{domain} — DKIM private key per domain
//	payment-blindsig-{tier}   — blind-sig private key per payment tier
//	payment-fakeid-tag        — HMAC key for primary_tag derivation
//	payment-fakeid-attest     — Ed25519 attestation key for tag attestations
//
// Role strings must not contain whitespace, control chars, or `..` path
// components. Validation happens at every API entry point.
type Role string

// Validate returns nil if the role string is well-formed.
func (r Role) Validate() error {
	return validateRole(string(r))
}

// GetRequest is the body of POST /keystore/get. The caller proves identity
// via the SGX attestation in their mTLS cert, which the server has already
// validated by the time this handler runs. The role string identifies
// which key to return.
type GetRequest struct {
	Role Role `json:"role"`
}

// GetResponse returns the requested key material plus a small bit of
// metadata. Key bytes are raw (caller decides how to interpret based on
// the role's documented type — Ed25519 seed for `*-fakeid-attest`, RSA
// PKCS1 DER for blind-sig, ECDSA EC-private for TLS, etc.).
type GetResponse struct {
	Key       []byte `json:"key"`
	KeyType   string `json:"key_type"` // ed25519 | rsa | ecdsa-p256 | aes-256 | raw
	CreatedAt int64  `json:"created_at"`
}

// DelegateRequest extends a role's MRENCLAVE allowlist by adding a new
// entry. The caller's own MRENCLAVE must already be on the role's
// allowlist (chained delegation), OR the request must carry an
// operator-break-glass signature (BreakGlass field).
type DelegateRequest struct {
	Role         Role     `json:"role"`
	NewMRENCLAVE [32]byte `json:"new_mrenclave"`

	// BreakGlass, if set, lets an offline operator credential add an
	// MRENCLAVE to the allowlist without requiring an already-allowlisted
	// enclave to vouch. Used for disaster recovery and first-time
	// bootstrap. The signature MUST cover SHA-256(role || new_mrenclave ||
	// nonce). Empty in normal chained delegations.
	BreakGlass *BreakGlassProof `json:"break_glass,omitempty"`
}

// BreakGlassProof carries an offline-operator Ed25519 signature for
// disaster-recovery allowlist mutations. Format is intentionally rigid
// to avoid signing-oracle confusion.
type BreakGlassProof struct {
	OperatorPubKeyHex string `json:"operator_pubkey_hex"` // 32-byte Ed25519 pubkey hex
	Nonce             string `json:"nonce"`               // random 16-byte hex, replay protection
	SignatureHex      string `json:"signature_hex"`       // Ed25519 sig over SHA-256(role || mrenclave || nonce)
}

// DelegateResponse confirms the allowlist mutation and echoes back the
// new full allowlist for the role so callers can sanity-check.
type DelegateResponse struct {
	Role             Role       `json:"role"`
	AllowedMRENCLAVE [][32]byte `json:"allowed_mrenclave"`
	DelegatedAt      int64      `json:"delegated_at"`
}

// RevokeRequest removes an MRENCLAVE from a role's allowlist. Used to
// retire old consumer versions after a soak window. Only callable with
// break-glass credential — there's no "consumer can self-revoke" path
// because that'd be a footgun (consumer accidentally revokes itself,
// gets locked out).
type RevokeRequest struct {
	Role         Role            `json:"role"`
	OldMRENCLAVE [32]byte        `json:"old_mrenclave"`
	BreakGlass   BreakGlassProof `json:"break_glass"`
}

// ProvisionRequest installs the initial key for a role. Idempotent only
// in the failure-after-write sense: if the role already has a stored
// key, Provision returns ErrAlreadyProvisioned and the existing key is
// untouched. Use Rotate (separate API, not yet defined) for legitimate
// key rotation.
type ProvisionRequest struct {
	Role       Role            `json:"role"`
	Key        []byte          `json:"key"`
	KeyType    string          `json:"key_type"`
	BreakGlass BreakGlassProof `json:"break_glass"`
}

// ProvisionResponse acks the provision and returns when it landed.
type ProvisionResponse struct {
	Role        Role  `json:"role"`
	ProvisionedAt int64 `json:"provisioned_at"`
}

// ListRequest enumerates the keystore's state for operator audit.
// Returns roles, allowlists, audit-log tail. Caller must present
// break-glass credential.
type ListRequest struct {
	BreakGlass    BreakGlassProof `json:"break_glass"`
	AuditTailSize int             `json:"audit_tail_size"` // 0 = no audit, >0 = last N entries
}

type ListResponse struct {
	Roles    []RoleInfo   `json:"roles"`
	AuditLog []AuditEntry `json:"audit_log,omitempty"`
}

type RoleInfo struct {
	Role             Role       `json:"role"`
	KeyType          string     `json:"key_type"`
	CreatedAt        int64      `json:"created_at"`
	AllowedMRENCLAVE [][32]byte `json:"allowed_mrenclave"`
}

// AuditEntry is one immutable row in the keystore's audit log. Entries
// form a hash chain: each new entry includes SHA-256(prev_entry_canonical)
// in PrevHash. Tampering with a past entry breaks the chain at every
// later entry. Operators verify chain integrity periodically.
type AuditEntry struct {
	Sequence  uint64    `json:"sequence"`     // monotonic, gap-free
	Timestamp time.Time `json:"timestamp"`    // UTC
	Action    string    `json:"action"`       // provision | get | delegate | revoke | startup | shutdown
	Role      Role      `json:"role,omitempty"`
	Actor     string    `json:"actor"`        // hex MRENCLAVE of caller, or "operator-break-glass:<pubkey-hex>"
	Detail    string    `json:"detail,omitempty"` // free-form, e.g. "delegated MRENCLAVE 0x1234..."
	PrevHash  string    `json:"prev_hash"`    // hex SHA-256 of canonical-JSON of previous entry
}

// validateRole enforces a conservative role-name grammar. Allowed:
// lowercase ASCII, digits, dash, dot, underscore. No leading/trailing
// dot or dash. Length 1-128.
func validateRole(s string) error {
	if len(s) == 0 || len(s) > 128 {
		return ErrInvalidRole
	}
	if s[0] == '-' || s[0] == '.' {
		return ErrInvalidRole
	}
	if s[len(s)-1] == '-' || s[len(s)-1] == '.' {
		return ErrInvalidRole
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_':
		default:
			return ErrInvalidRole
		}
	}
	return nil
}
