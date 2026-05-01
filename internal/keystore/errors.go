package keystore

import "errors"

// Sentinel errors. Callers MAY match with errors.Is to discriminate;
// servers translate to HTTP statuses (see server.go).
var (
	// ErrInvalidRole — role name violated the grammar.
	ErrInvalidRole = errors.New("keystore: invalid role")

	// ErrAlreadyProvisioned — Provision called on a role that already
	// has stored key material. Use Rotate (when implemented) for
	// legitimate key rotation; never overwrite via Provision.
	ErrAlreadyProvisioned = errors.New("keystore: role already provisioned")

	// ErrRoleNotFound — Get called for a role with no stored key.
	ErrRoleNotFound = errors.New("keystore: role not found")

	// ErrNotAllowed — caller's MRENCLAVE is not on the role's allowlist.
	ErrNotAllowed = errors.New("keystore: caller not on role allowlist")

	// ErrBreakGlassRequired — operation requires break-glass proof but
	// none was supplied.
	ErrBreakGlassRequired = errors.New("keystore: break-glass credential required")

	// ErrBreakGlassInvalid — break-glass signature did not verify, or
	// the operator pubkey is not the trusted one.
	ErrBreakGlassInvalid = errors.New("keystore: break-glass signature invalid")

	// ErrBreakGlassReplay — break-glass nonce was reused.
	ErrBreakGlassReplay = errors.New("keystore: break-glass nonce replay")

	// ErrCorruptedState — sealed state on disk failed integrity
	// checks (audit-log hash chain broken, JSON unparseable, etc.).
	// This is fatal at startup; operator must investigate.
	ErrCorruptedState = errors.New("keystore: sealed state corrupted")
)
