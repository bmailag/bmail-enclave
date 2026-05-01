package storage

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"

	bmcrypto "github.com/bmailag/bmail/internal/crypto"
)

// EncryptedAddress holds the X25519+XChaCha20-Poly1305 envelope for a
// single email address encrypted to a user's bmail public key. Used by
// the contacts and blocked_senders tables to store addresses at rest
// without exposing them to passive DB reads.
//
// Same envelope format the web/mobile clients use for bmail-to-bmail
// mail (subject + body), reused here with body=empty and subject=address.
type EncryptedAddress struct {
	Encrypted    []byte // ciphertext (corresponds to encrypted_subject)
	Ephemeral    []byte // ephemeral X25519 public key
	EncryptedKey []byte // wrapped message key
}

// EncryptAddressForUser encrypts a single email address to the given
// X25519 public key bytes. Use this when the server has cleartext at
// hand (e.g. inbound SMTP envelope, contact creation API request) and
// needs to persist it without storing plaintext.
func EncryptAddressForUser(userPubKey []byte, address string) (*EncryptedAddress, error) {
	if len(userPubKey) != 32 {
		return nil, fmt.Errorf("invalid user pubkey length: %d", len(userPubKey))
	}
	pub, err := ecdh.X25519().NewPublicKey(userPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse user pubkey: %w", err)
	}
	// Treat the address as the "subject" of an empty message. This reuses
	// the existing envelope format with no schema changes.
	enc, err := bmcrypto.EncryptMessage(pub, []byte(address), []byte{})
	if err != nil {
		return nil, fmt.Errorf("encrypt address: %w", err)
	}
	return &EncryptedAddress{
		Encrypted:    enc.EncryptedSubject,
		Ephemeral:    enc.EphemeralPubkey,
		EncryptedKey: enc.EncryptedMessageKey,
	}, nil
}

// EncryptAddressForUserHybrid encrypts a single email address using
// hybrid X25519 + ML-KEM-768 when userKEMPubKey is non-nil.
// Falls back to classical X25519 when userKEMPubKey is nil.
func EncryptAddressForUserHybrid(userPubKey, userKEMPubKey []byte, address string) (*EncryptedAddress, error) {
	if len(userPubKey) != 32 {
		return nil, fmt.Errorf("invalid user pubkey length: %d", len(userPubKey))
	}
	pub, err := ecdh.X25519().NewPublicKey(userPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse user pubkey: %w", err)
	}
	var kemEK *mlkem.EncapsulationKey768
	if len(userKEMPubKey) > 0 {
		kemEK, err = bmcrypto.MLKEMEncapsulationKeyFromBytes(userKEMPubKey)
		if err != nil {
			return nil, fmt.Errorf("parse user KEM pubkey: %w", err)
		}
	}
	enc, err := bmcrypto.EncryptMessageHybrid(pub, kemEK, []byte(address), []byte{})
	if err != nil {
		return nil, fmt.Errorf("encrypt address: %w", err)
	}
	return &EncryptedAddress{
		Encrypted:    enc.EncryptedSubject,
		Ephemeral:    enc.EphemeralPubkey,
		EncryptedKey: enc.EncryptedMessageKey,
	}, nil
}
