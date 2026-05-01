//go:build ego

package tee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
)

// EGoRuntime is a TEERuntime backed by real Intel SGX via the EGo framework.
// Seal/Unseal use MRSIGNER-based sealing so that code updates do not
// invalidate sealed state.
type EGoRuntime struct{}

var _ TEERuntime = (*EGoRuntime)(nil)

// NewEGoRuntime returns a new EGo SGX runtime.
func NewEGoRuntime() *EGoRuntime {
	return &EGoRuntime{}
}

// NewRuntime returns the appropriate TEE runtime for the build.
// With the "ego" build tag, this returns EGoRuntime.
func NewRuntime() TEERuntime {
	return NewEGoRuntime()
}

// SelfID returns the hex-encoded MRENCLAVE measurement from the enclave's
// self-report, identifying the exact code running inside the enclave.
func (e *EGoRuntime) SelfID() string {
	report, err := enclave.GetSelfReport()
	if err != nil {
		return "ego-unknown"
	}
	return fmt.Sprintf("%x", report.UniqueID)
}

// GenerateKey generates a real keypair inside the enclave.
func (e *EGoRuntime) GenerateKey(algorithm string) ([]byte, []byte, error) {
	switch algorithm {
	case "x25519":
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
		}
		return priv.PublicKey().Bytes(), priv.Bytes(), nil

	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
		}
		return []byte(pub), []byte(priv), nil

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// Attest produces a real SGX remote-attestation report binding userData
// to the enclave measurement.
func (e *EGoRuntime) Attest(userData []byte) ([]byte, error) {
	report, err := enclave.GetRemoteReport(userData)
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	return report, nil
}

// Seal encrypts plaintext using the enclave's MRSIGNER-derived key.
// This allows the sealed data to survive enclave code updates as long
// as the signer identity remains the same.
func (e *EGoRuntime) Seal(plaintext []byte) ([]byte, error) {
	ciphertext, err := ecrypto.SealWithProductKey(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return ciphertext, nil
}

// Now returns the current UTC time. In a production SGX enclave, this should
// be enhanced to use an attested time source (e.g., Intel AESM trusted time
// or an attested NTP relay). Currently uses the host-provided clock, which the
// EGo runtime exposes to enclave code.
func (e *EGoRuntime) Now() time.Time {
	return time.Now().UTC()
}

// Unseal decrypts ciphertext that was previously sealed by this enclave signer.
func (e *EGoRuntime) Unseal(ciphertext []byte) ([]byte, error) {
	plaintext, err := ecrypto.Unseal(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return plaintext, nil
}

// SealUnique encrypts plaintext using the enclave's MRENCLAVE-derived key.
// Sealed ciphertext can ONLY be unsealed by an enclave running the exact
// same MRENCLAVE — code drift makes the data unrecoverable. Used by the
// keystore enclave per ADR-006 to ensure long-lived secrets cannot be
// extracted by an operator who re-signs a malicious enclave with the same
// MRSIGNER but different code.
func (e *EGoRuntime) SealUnique(plaintext []byte) ([]byte, error) {
	ciphertext, err := ecrypto.SealWithUniqueKey(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("seal unique: %w", err)
	}
	return ciphertext, nil
}

// UnsealUnique decrypts ciphertext sealed under this exact MRENCLAVE.
func (e *EGoRuntime) UnsealUnique(ciphertext []byte) ([]byte, error) {
	plaintext, err := ecrypto.Unseal(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unseal unique: %w", err)
	}
	return plaintext, nil
}
