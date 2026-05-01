package keystore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// breakGlass verifies operator-supplied Ed25519 signatures used to
// authorize bootstrap and disaster-recovery operations (Provision,
// Revoke, List). The operator's public key is fixed at keystore boot
// (env var KEYSTORE_BREAK_GLASS_PUBKEY_HEX) and the matching private
// key is held offline — same custody profile as `private.pem.backup`.
//
// Replay protection is per-process: each successful break-glass call
// inserts its nonce into seenNonces; a second call with the same nonce
// errs out with ErrBreakGlassReplay. The operator's tooling MUST
// generate a fresh nonce for every invocation.
//
// On keystore restart the in-memory nonce set resets — that's
// acceptable because break-glass calls are inherently rare and
// operator-driven, and the offline operator key is itself the
// trust anchor; nonce replay just limits the window an attacker has
// to replay an OBSERVED break-glass call. Without observation, replay
// is impossible because nonces are random 16 bytes.
type breakGlass struct {
	mu          sync.Mutex
	expectedPub ed25519.PublicKey
	seenNonces  map[string]struct{}
}

// newBreakGlass parses the hex-encoded operator public key from the
// supplied string. Empty string disables break-glass entirely; in that
// mode every BreakGlass-required call returns ErrBreakGlassInvalid.
// Tests use empty + a separate code path; production MUST set this.
func newBreakGlass(operatorPubHex string) (*breakGlass, error) {
	bg := &breakGlass{seenNonces: map[string]struct{}{}}
	if operatorPubHex == "" {
		return bg, nil // disabled mode
	}
	if len(operatorPubHex) != 64 {
		return nil, fmt.Errorf("operator pubkey hex must be 64 chars, got %d", len(operatorPubHex))
	}
	pub, err := hex.DecodeString(operatorPubHex)
	if err != nil {
		return nil, fmt.Errorf("decode operator pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("operator pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	bg.expectedPub = ed25519.PublicKey(pub)
	return bg, nil
}

// Verify checks the proof's signature over canonical(action, role,
// payload, nonce). Returns nil if valid AND nonce hasn't been used
// in this process lifetime.
//
// Canonical signing input: action || ":" || role || ":" || hex(payload)
// || ":" || nonce.  Where:
//   - action is one of "provision" | "delegate-add" | "revoke" | "list"
//   - role is the role string (or "" for list)
//   - payload is operation-specific byte string (e.g., MRENCLAVE for
//     delegate, key bytes for provision, or empty for revoke/list)
//   - nonce is the proof's hex string verbatim
func (bg *breakGlass) Verify(proof BreakGlassProof, action string, role Role, payload []byte) error {
	if bg.expectedPub == nil {
		return ErrBreakGlassInvalid
	}
	if proof.OperatorPubKeyHex == "" || proof.SignatureHex == "" || proof.Nonce == "" {
		return ErrBreakGlassRequired
	}
	if proof.OperatorPubKeyHex != hex.EncodeToString(bg.expectedPub) {
		return ErrBreakGlassInvalid
	}
	sig, err := hex.DecodeString(proof.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBreakGlassInvalid
	}
	if len(proof.Nonce) < 16 {
		// Operator should use at least 16 hex chars (8 bytes).
		// Smaller nonces are rejected to keep the keyspace large.
		return ErrBreakGlassInvalid
	}

	bg.mu.Lock()
	if _, seen := bg.seenNonces[proof.Nonce]; seen {
		bg.mu.Unlock()
		return ErrBreakGlassReplay
	}
	bg.mu.Unlock()

	signed := canonicalBreakGlassSigningInput(action, role, payload, proof.Nonce)
	if !ed25519.Verify(bg.expectedPub, signed, sig) {
		return ErrBreakGlassInvalid
	}

	bg.mu.Lock()
	bg.seenNonces[proof.Nonce] = struct{}{}
	bg.mu.Unlock()
	return nil
}

// canonicalBreakGlassSigningInput is the deterministic byte string the
// operator's tool must reproduce when signing. SHA-256 of the rendered
// form so signing tools can hash without dealing with the role/payload
// length prefixing.
func canonicalBreakGlassSigningInput(action string, role Role, payload []byte, nonce string) []byte {
	rendered := action + ":" + string(role) + ":" + hex.EncodeToString(payload) + ":" + nonce
	sum := sha256.Sum256([]byte(rendered))
	return sum[:]
}

// Enabled reports whether break-glass is configured. Used by handlers
// to fail closed in production if it isn't.
func (bg *breakGlass) Enabled() bool {
	return bg.expectedPub != nil
}
