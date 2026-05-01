package keystore

import (
	"encoding/hex"
	"fmt"
)

// encodeMRENCLAVEHex returns the lowercase 64-character hex encoding of
// a 32-byte MRENCLAVE. Used as the stable on-disk and on-wire format.
func encodeMRENCLAVEHex(m [32]byte) string {
	return hex.EncodeToString(m[:])
}

// decodeMRENCLAVEHex parses a 64-character hex string back into a 32-byte
// MRENCLAVE. Rejects anything else; case-insensitive on input.
func decodeMRENCLAVEHex(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("mrenclave hex must be 64 chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("decode mrenclave hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}
