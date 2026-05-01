package storage

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	bmcrypto "github.com/bmailag/bmail/internal/crypto"
)

// MessageHeaders is the JSON-serializable shape of the headers blob
// stored in messages.encrypted_headers (Phase B3). It mirrors the
// shape produced by smtp.buildRawMeta for inbound mail — a flat map
// of canonical RFC 5322 header names to their value lists — so any
// existing client decoder for encrypted_raw_meta can be reused for
// `encrypted_headers` with no schema differences.
//
// For sender-side rows (sent / drafts / forward / calendar / welcome
// / bounce) the mail service synthesizes a minimal envelope with just
// the addressing headers; for inbound the smtp pipeline copies the
// full parsed header set.
type MessageHeaders struct {
	Headers map[string][]string `json:"Headers"`
}

// MarshalMessageHeaders serializes the headers map to the canonical
// JSON shape used by encrypted_headers. Returned bytes are intended
// to be passed straight into crypto.EncryptMessageWithHeaders.
func MarshalMessageHeaders(headers map[string][]string) ([]byte, error) {
	return json.Marshal(MessageHeaders{Headers: headers})
}

// EncryptStandaloneHeaders encrypts a headers JSON blob to a recipient
// public key with its OWN envelope (its own ephemeral pubkey + wrapped
// message key). Use this when no body is being encrypted at the same
// time — for example the backfill tool re-keying historical rows
// where the body envelope is already locked in.
//
// Returns the full crypto.EncryptedMessage; callers persist
// EphemeralPubkey + EncryptedMessageKey + EncryptedHeaders. The body
// and subject slots are intentionally empty — the headers blob is
// the only payload here.
func EncryptStandaloneHeaders(userPubKey []byte, headersJSON []byte) (*bmcrypto.EncryptedMessage, error) {
	if len(userPubKey) != 32 {
		return nil, fmt.Errorf("invalid user pubkey length: %d", len(userPubKey))
	}
	pub, err := ecdh.X25519().NewPublicKey(userPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse user pubkey: %w", err)
	}
	enc, err := bmcrypto.EncryptMessageWithHeaders(pub, []byte{}, []byte{}, headersJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt headers: %w", err)
	}
	return enc, nil
}

// BuildSimpleHeadersJSON synthesizes a small RFC-5322-shaped headers
// JSON for a sender-side message row from the few fields we know on
// the server (addresses + threading metadata). Display names are
// preserved as-is when the caller passes pre-formatted strings like
// "Alice Smith <alice@example.com>".
//
// `from` is a single value; `to`/`cc`/`bcc` may be multi-value. Empty
// slices are omitted from the output to keep the blob small.
func BuildSimpleHeadersJSON(from string, to, cc, bcc []string, dateRFC, messageID, inReplyTo, references string) ([]byte, error) {
	headers := map[string][]string{}
	if from != "" {
		headers["From"] = []string{from}
	}
	if len(to) > 0 {
		headers["To"] = to
	}
	if len(cc) > 0 {
		headers["Cc"] = cc
	}
	if len(bcc) > 0 {
		headers["Bcc"] = bcc
	}
	if dateRFC != "" {
		headers["Date"] = []string{dateRFC}
	}
	if messageID != "" {
		headers["Message-ID"] = []string{messageID}
	}
	if inReplyTo != "" {
		headers["In-Reply-To"] = []string{inReplyTo}
	}
	if references != "" {
		headers["References"] = []string{references}
	}
	return MarshalMessageHeaders(headers)
}
