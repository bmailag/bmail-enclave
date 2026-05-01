package tee

import (
	"fmt"
	"log/slog"
	"os"
)

// LoadOrSealBytes loads a sealed key from disk, or calls generate to create one,
// seals it, and persists it. This is the canonical pattern for persistent key
// material in TEE environments.
//
// The envOverride parameter, if non-empty, names an environment variable that
// provides the raw key bytes directly (hex-decoded by the caller). If set, the
// env value is used and no seal/unseal occurs.
//
// The sealedPath is the filesystem path for sealed key storage.
func LoadOrSealBytes(runtime TEERuntime, sealedPath string, generate func() ([]byte, error)) ([]byte, error) {
	// Try to unseal from disk.
	sealedData, err := os.ReadFile(sealedPath)
	if err == nil && len(sealedData) > 0 {
		plaintext, err := runtime.Unseal(sealedData)
		if err != nil {
			slog.Error("failed to unseal key, will generate new one — check enclave identity", "path", sealedPath, "error", err)
		} else {
			slog.Info("key unsealed from persistent storage", "path", sealedPath)
			return plaintext, nil
		}
	}

	// Generate new key material.
	keyBytes, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Seal and persist.
	sealed, err := runtime.Seal(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}

	if err := os.WriteFile(sealedPath, sealed, 0600); err != nil {
		slog.Warn("could not persist sealed key", "path", sealedPath, "error", err)
	} else {
		slog.Info("key generated, sealed, and persisted", "path", sealedPath)
	}

	return keyBytes, nil
}

// LoadOrSealUniqueBytes is the MRENCLAVE-bound variant of LoadOrSealBytes.
// Seals + unseals via runtime.SealUnique / runtime.UnsealUnique, so the
// stored key is recoverable ONLY by an enclave running the exact same
// MRENCLAVE that sealed it. Code drift makes the file unrecoverable —
// caller's `generate` runs and a fresh key takes its place.
//
// Use this for keys that:
//   - SHOULD survive a crash/reboot of the same enclave version, AND
//   - SHOULD NOT be recoverable by an operator who re-signs a malicious
//     enclave with the same MRSIGNER (which can unseal MRSIGNER-sealed
//     state from this enclave).
//
// Examples: gateway TLS key (autocert + GTS handles re-issue cheaply on
// drift); smtp-inbound TLS key (daneUpdate auto-publishes new SPKI).
//
// Do NOT use for keys that must outlive enclave version changes (those
// belong in the keystore enclave per ADR-006).
func LoadOrSealUniqueBytes(runtime TEERuntime, sealedPath string, generate func() ([]byte, error)) ([]byte, error) {
	sealedData, err := os.ReadFile(sealedPath)
	if err == nil && len(sealedData) > 0 {
		plaintext, err := runtime.UnsealUnique(sealedData)
		if err != nil {
			slog.Info("MRENCLAVE-sealed key did not unseal, generating fresh (expected on enclave version change)",
				"path", sealedPath, "error", err)
		} else {
			slog.Info("key unsealed from persistent storage (MRENCLAVE-bound)", "path", sealedPath)
			return plaintext, nil
		}
	}

	keyBytes, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	sealed, err := runtime.SealUnique(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("seal-unique key: %w", err)
	}
	if err := os.WriteFile(sealedPath, sealed, 0600); err != nil {
		slog.Warn("could not persist MRENCLAVE-sealed key", "path", sealedPath, "error", err)
	} else {
		slog.Info("key generated, MRENCLAVE-sealed, and persisted", "path", sealedPath)
	}
	return keyBytes, nil
}
