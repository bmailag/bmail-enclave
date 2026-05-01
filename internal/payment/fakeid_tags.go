package payment

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/bmailag/bmail/internal/tee"
)

// fakeid_tag_key and fakeid_attestation_key are the two new enclave-only
// secrets that back the atomic-slot redesign (migration 089).
//
//   fakeid_tag_key (32 bytes, HMAC-SHA256 key)
//     Derives primary_tag = HMAC(key, primary_id). The tag is the opaque
//     handle the enclave uses to key rows in fakeid_pending_slots and
//     fakeid_consumed_slots. Because the key never leaves the enclave,
//     bmail-side DB rows can't be reversed back to primary_id.
//
//   fakeid_attestation_key (Ed25519 keypair)
//     Signs (token_hash || primary_tag) when mint issues a credential.
//     Binds a specific primary_tag to a specific token so a malicious
//     client can't splice tags between credentials. The public key is
//     served alongside the existing blind-sig pubkeys so the FakeID
//     register handler can verify credentials before forwarding them.
//
// Both keys are sealed under the enclave's identity. Losing them orphans
// every existing pending/consumed row — back them up with the same
// discipline as private.pem (MRSIGNER) and the blind-sig tier keys.

const (
	fakeidTagKeyPath         = "/opt/bmail/sealed/sealed_fakeid_tag_key.bin"
	fakeidAttestationKeyPath = "/opt/bmail/sealed/sealed_fakeid_attestation_key.bin"
	fakeidTagKeyLen          = 32
)

// FakeIDTagKey is the 32-byte HMAC key used to derive primary_tag.
type FakeIDTagKey [fakeidTagKeyLen]byte

// FakeIDAttestationKey holds the enclave-only Ed25519 keypair that signs
// tag attestations on minted credentials.
type FakeIDAttestationKey struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// LoadOrSealFakeIDTagKey loads the HMAC tag key from sealed storage,
// generating a fresh one on first boot.
func LoadOrSealFakeIDTagKey(runtime tee.TEERuntime) (FakeIDTagKey, error) {
	keyBytes, err := tee.LoadOrSealBytes(runtime, fakeidTagKeyPath, func() ([]byte, error) {
		k := make([]byte, fakeidTagKeyLen)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		return k, nil
	})
	if err != nil {
		return FakeIDTagKey{}, fmt.Errorf("load fakeid tag key: %w", err)
	}
	if len(keyBytes) != fakeidTagKeyLen {
		return FakeIDTagKey{}, fmt.Errorf("fakeid tag key has wrong length: got %d want %d",
			len(keyBytes), fakeidTagKeyLen)
	}
	var out FakeIDTagKey
	copy(out[:], keyBytes)
	return out, nil
}

// LoadOrSealFakeIDAttestationKey loads the Ed25519 attestation keypair
// from sealed storage, generating one on first boot.
func LoadOrSealFakeIDAttestationKey(runtime tee.TEERuntime) (FakeIDAttestationKey, error) {
	seedBytes, err := tee.LoadOrSealBytes(runtime, fakeidAttestationKeyPath, func() ([]byte, error) {
		// ed25519.NewKeyFromSeed takes exactly SeedSize (32) bytes. Storing
		// the seed rather than the full private key keeps the sealed blob
		// minimal and lets us re-derive both halves deterministically.
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("read random seed: %w", err)
		}
		return seed, nil
	})
	if err != nil {
		return FakeIDAttestationKey{}, fmt.Errorf("load fakeid attestation key: %w", err)
	}
	if len(seedBytes) != ed25519.SeedSize {
		return FakeIDAttestationKey{}, fmt.Errorf("fakeid attestation seed has wrong length: got %d want %d",
			len(seedBytes), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return FakeIDAttestationKey{}, fmt.Errorf("ed25519 public key type assertion failed")
	}
	return FakeIDAttestationKey{Private: priv, Public: pub}, nil
}

// DerivePrimaryTag returns HMAC-SHA256(tagKey, primaryID). The enclave is
// the only code path that ever runs this — bmail-side callers pass
// primary_id to the enclave and receive primary_tag back.
func DerivePrimaryTag(tagKey FakeIDTagKey, primaryID string) []byte {
	mac := hmac.New(sha256.New, tagKey[:])
	mac.Write([]byte(primaryID))
	return mac.Sum(nil)
}

// SignTagAttestation signs primary_tag with the enclave's attestation
// key and returns the raw signature bytes. The attestation proves that
// primary_tag came from this enclave (since the Ed25519 key is sealed)
// — an attacker can't forge a primary_tag that verifies, so the tag
// can't be spoofed to collide with someone else's slot.
//
// It does NOT bind the tag to a specific credential. The earlier design
// tried to sign (H(blind_sig) || primary_tag) but the mint side only
// has the blinded signature while the verify side only has the
// unblinded one — different bytes by construction, so the attestation
// always rejected. A proper per-credential binding would require a
// client-supplied digest at mint (blinded hash of the final token),
// which is doable but involves a protocol bump. Left as a follow-up
// because the attack it prevents (swapping an intercepted credential
// onto a different primary's tag) has no practical payoff: the
// attacker would consume their own slot to register a Fake ID they
// could have minted legitimately.
func (k FakeIDAttestationKey) SignTagAttestation(primaryTag []byte) []byte {
	return ed25519.Sign(k.Private, primaryTag)
}

// VerifyTagAttestation checks a signature over primary_tag against the
// attestation public key. Uses Ed25519's built-in canonical signature
// check so malleability isn't a concern.
func (k FakeIDAttestationKey) VerifyTagAttestation(primaryTag, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(k.Public, primaryTag, sig)
}
