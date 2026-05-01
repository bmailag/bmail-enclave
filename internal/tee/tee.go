// Package tee provides an abstraction layer for Trusted Execution Environment
// operations. It defines the TEERuntime interface and provides both a simulation
// backend (for development/testing) and an EGo SGX backend (for production).
package tee

import "time"

// TEERuntime abstracts TEE operations so that the rest of the system can work
// with either a real SGX enclave (via EGo) or a simulated environment.
type TEERuntime interface {
	// GenerateKey generates a keypair for the given algorithm.
	// Supported algorithms: "x25519", "ed25519".
	// Returns the raw public and private key bytes.
	GenerateKey(algorithm string) (publicKey []byte, privateKey []byte, err error)

	// Attest produces a remote-attestation report (SGX quote) that binds
	// the given userData to the enclave measurement.
	Attest(userData []byte) (report []byte, err error)

	// Seal encrypts plaintext using a key derived from the enclave identity
	// (MRSIGNER in production). The ciphertext can only be unsealed by the
	// same enclave signer.
	Seal(plaintext []byte) (ciphertext []byte, err error)

	// Unseal decrypts ciphertext that was previously sealed by this enclave.
	Unseal(ciphertext []byte) (plaintext []byte, err error)

	// SealUnique encrypts plaintext using a key derived from the enclave's
	// unique measurement (MRENCLAVE). The ciphertext can ONLY be unsealed
	// by an enclave with the exact same MRENCLAVE — no other enclave signed
	// by the same MRSIGNER can recover it. Used by the keystore enclave to
	// guarantee that long-lived keys cannot be extracted by an operator
	// who re-signs a malicious enclave with the same MRSIGNER. See ADR-006.
	SealUnique(plaintext []byte) (ciphertext []byte, err error)

	// UnsealUnique decrypts ciphertext that was previously SealUnique'd by
	// this exact MRENCLAVE.
	UnsealUnique(ciphertext []byte) (plaintext []byte, err error)

	// SelfID returns the enclave's identity string. In production this is the
	// hex-encoded MRENCLAVE measurement from the SGX report. In simulation
	// mode it returns a dev marker.
	SelfID() string

	// Now returns the current UTC time from a trusted source. In production
	// SGX, this should use an attested time service. In simulation mode it
	// falls back to the host clock.
	Now() time.Time
}
