package tee

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/KarpelesLab/echeck"
)

// NewEnclaveClient creates an HTTP client that verifies the remote server's
// SGX attestation on every TLS connection. Use this for enclave-to-enclave
// communication (e.g., gateway → payment) to maintain the trust chain.
//
// expectedMRSigner should be set to the hex-encoded MRSIGNER of the signing
// key used to build the enclaves. Since all bmail enclaves share the same
// signing key, this ensures the remote is signed by the same trusted key.
//
// In dev mode (sim runtime), pass empty strings to skip verification —
// sim certs don't contain SGX quotes.
func NewEnclaveClient(expectedMRSigner string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We verify SGX quote, not CA
				VerifyConnection: func(cs tls.ConnectionState) error {
					if expectedMRSigner == "" {
						return nil // Dev mode — skip verification
					}
					return verifyEnclaveConnection(cs, expectedMRSigner)
				},
			},
		},
	}
}

func verifyEnclaveConnection(cs tls.ConnectionState, expectedMRSigner string) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("enclave-client: no peer certificate")
	}

	cert := cs.PeerCertificates[0]

	quote, err := echeck.ExtractQuote(cert)
	if err != nil {
		return fmt.Errorf("enclave-client: %w", err)
	}

	if err := echeck.VerifyQuote(cert, quote); err != nil {
		return fmt.Errorf("enclave-client: quote verification failed: %w", err)
	}

	// All bmail enclaves share the same signing key (MRSIGNER), so verify that.
	if expectedMRSigner != "" {
		info := quote.GetQuoteInfo()
		if fmt.Sprintf("%x", info.MRSigner) != expectedMRSigner {
			return fmt.Errorf("enclave-client: MRSIGNER mismatch: got %x, want %s", info.MRSigner, expectedMRSigner)
		}
	}

	return nil
}
