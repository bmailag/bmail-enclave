package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// blindIndexSecret is the server-wide HMAC key used to compute blind indexes
// for encrypted-at-rest fields like contacts.address_blind_index and
// blocked_senders.sender_blind_index. Loaded from BLIND_INDEX_SECRET env var
// (32 bytes hex) at startup.
//
// Threat model: a passive read of the database reveals only HMACs and
// ciphertext — no plaintext addresses. An attacker who ALSO has the secret
// (e.g. via env-var compromise) can probe by HMAC'ing candidate addresses,
// which is a meaningful weakening but still much harder than reading
// plaintext columns. The encryption layer (X25519+XChaCha20 to user's
// pubkey) prevents recovery of the address itself even with the secret.
var blindIndexSecret []byte

// InitBlindIndexSecret installs the server-wide blind index HMAC key.
// Must be called at startup with a 32-byte key.
func InitBlindIndexSecret(key []byte) {
	blindIndexSecret = make([]byte, len(key))
	copy(blindIndexSecret, key)
}

// ComputeAddressBlindIndex returns a stable lookup token for an email
// address, scoped to a specific user. Uses HMAC-SHA256(secret, scope ||
// userID || normalized_address). The "scope" string ensures contact
// blind indexes can't be matched against block-list blind indexes even
// for the same user+address pair.
//
// Returns lowercase hex.
func ComputeAddressBlindIndex(scope string, userID uuid.UUID, address string) string {
	if blindIndexSecret == nil {
		// Caller is responsible for ensuring InitBlindIndexSecret was called.
		// Returning an empty string here would silently break uniqueness;
		// returning a constant is worse. Panic to fail loudly during
		// development; production startup ensures the key is set.
		panic("blind index secret not initialized — call storage.InitBlindIndexSecret at startup")
	}
	normalized := strings.ToLower(strings.TrimSpace(address))
	mac := hmac.New(sha256.New, blindIndexSecret)
	mac.Write([]byte(scope))
	mac.Write([]byte(":"))
	mac.Write(userID[:])
	mac.Write([]byte(":"))
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}

// Scope constants. Keep these stable — changing them invalidates all
// existing blind indexes in production.
const (
	BlindScopeContact       = "contact-address-v1"
	BlindScopeBlockSender   = "block-sender-v1"
	BlindScopeMessageSender = "message-sender-v1"
)
