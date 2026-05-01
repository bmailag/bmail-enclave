package config

import (
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/bytemare/opaque"
)

// LoadOPAQUEKeys loads OPAQUE key material from OPAQUE_SEED, OPAQUE_SERVER_KEY,
// and OPAQUE_SERVER_PUBKEY environment variables (hex-encoded).
// In development, generates fresh keys if not set (with a warning).
// In production, returns an error if any are missing.
//
// F-02 note: The hex string intermediates (seedHex, privHex, pubHex) cannot be
// reliably zeroed because Go strings are immutable and backed by read-only memory.
// The returned byte slices persist for the lifetime of the OPAQUE server.
// In production SGX deployments, all process memory is enclave-protected,
// mitigating this concern. For non-SGX deployments, the keys loaded from env
// vars are already in process memory regardless.
func LoadOPAQUEKeys() (oprfSeed, serverPrivKey, serverPubKey []byte, err error) {
	loadEnvDev()

	seedHex := Optional("OPAQUE_SEED")
	privHex := Optional("OPAQUE_SERVER_KEY")
	pubHex := Optional("OPAQUE_SERVER_PUBKEY")

	if seedHex != "" && privHex != "" && pubHex != "" {
		oprfSeed, err = hex.DecodeString(seedHex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode OPAQUE_SEED: %w", err)
		}
		serverPrivKey, err = hex.DecodeString(privHex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode OPAQUE_SERVER_KEY: %w", err)
		}
		serverPubKey, err = hex.DecodeString(pubHex)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode OPAQUE_SERVER_PUBKEY: %w", err)
		}
		return oprfSeed, serverPrivKey, serverPubKey, nil
	}

	if IsProduction() {
		return nil, nil, nil, fmt.Errorf("OPAQUE_SEED, OPAQUE_SERVER_KEY, and OPAQUE_SERVER_PUBKEY must be set in production")
	}

	slog.Warn("generating fresh OPAQUE keys, not for production")
	conf := opaque.DefaultConfiguration()
	oprfSeed = conf.GenerateOPRFSeed()
	serverPrivKey, serverPubKey = conf.KeyGen()
	return oprfSeed, serverPrivKey, serverPubKey, nil
}
