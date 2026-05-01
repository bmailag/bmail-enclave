package keystore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/KarpelesLab/echeck"
)

// Authentication of inbound RPCs is two-layer:
//
//  1. TLS handshake — the keystore presents its own attestation cert
//     (server-side SGX quote, like every other bmail enclave's TLS
//     handshake), and REQUIRES a client cert from the caller.
//  2. Quote validation on the client cert — done in VerifyPeerCertificate.
//     We extract the SGX quote from the cert's X.509 extension, verify
//     it against the Intel chain, and pull MRENCLAVE + MRSIGNER. Stash
//     them in a context-bound struct so the HTTP handler can authorize.
//
// The keystore enforces TWO orthogonal checks at handler time:
//
//   - MRSIGNER must equal the bmail signing identity. (Anyone can build
//     and sign their own enclave, but they can't get bmail's MRSIGNER
//     without bmail's offline `private.pem`. This is the operational
//     "is this an unmodified bmail enclave at all?" gate.)
//   - MRENCLAVE must be on the per-role allowlist for the requested
//     role. (This is the "is this the EXACT code we authorized for this
//     specific key?" gate.)
//
// Either check failing returns 403. Both passing → handler proceeds.

// peerInfo is what the connection-level quote validator extracts and
// stashes for handler-time authorization decisions.
type peerInfo struct {
	MRENCLAVE [32]byte
	MRSIGNER  [32]byte

	// CertHash is SHA-256 of the peer's leaf cert DER. Useful for
	// audit-log entries so we can correlate "who called what" without
	// dumping the full cert.
	CertHash [32]byte
}

// peerCtxKey is the unexported context key for stashing peerInfo.
type peerCtxKey struct{}

// withPeer returns a child context with the peerInfo attached.
func withPeer(ctx context.Context, p *peerInfo) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, p)
}

// peerFromContext retrieves the peerInfo set by VerifyPeerCertificate.
// Returns nil if not set (which means the request bypassed our auth path
// — handlers MUST treat that as fatal).
func peerFromContext(ctx context.Context) *peerInfo {
	v, _ := ctx.Value(peerCtxKey{}).(*peerInfo)
	return v
}

// peerStore lets the TLS layer (which has access to the connection but
// not the per-request context) hand off the validated peerInfo to the
// HTTP handler layer (which has the context but not the connection).
//
// We key by the TLS connection's leaf-cert SHA-256 — guaranteed unique
// per concurrent handshake on this listener, and stable across the
// connection's request lifetime. The HTTP server's ConnContext callback
// reads the cert from the *tls.Conn and looks up the peerInfo here.
type peerStore struct {
	mu      sync.Mutex
	entries map[[32]byte]*peerInfo
}

func newPeerStore() *peerStore {
	return &peerStore{entries: map[[32]byte]*peerInfo{}}
}

func (s *peerStore) put(certHash [32]byte, info *peerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[certHash] = info
}

func (s *peerStore) get(certHash [32]byte) *peerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[certHash]
}

func (s *peerStore) drop(certHash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, certHash)
}

// makeVerifyPeerCertificate returns a tls.Config.VerifyPeerCertificate
// hook that BEST-EFFORT extracts the SGX quote from the client cert
// and stashes the resulting peerInfo in `peers` keyed by cert hash.
// The HTTP server's per-connection middleware later retrieves it.
//
// expectedMRSIGNER is the hex-encoded bmail signing identity. When
// non-empty AND the cert carries a valid SGX quote, the MRSIGNER
// must match — protects against a non-bmail enclave talking to the
// keystore.
//
// Important: the TLS layer never fails the handshake based on
// missing or invalid quote. Per-handler auth then decides:
//   - handleGet requires peer.MRENCLAVE to be on the role's
//     allowlist (zero MRENCLAVE always denies)
//   - handleProvision / handleDelegate / handleRevoke / handleList
//     require an operator break-glass proof, independent of TLS
//
// This split lets operator tools (which don't run inside an SGX
// enclave and therefore can't present an attested cert) call the
// break-glass-gated mutating endpoints with any TLS cert, while
// consumer enclaves still get strict MRSIGNER + MRENCLAVE checks
// before any sealed key material is returned.
func makeVerifyPeerCertificate(peers *peerStore, expectedMRSIGNER string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("keystore: client presented no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("keystore: parse client cert: %w", err)
		}

		certHash := sha256.Sum256(cert.Raw)
		info := &peerInfo{CertHash: certHash}

		quote, qerr := echeck.ExtractQuote(cert)
		if qerr == nil {
			if vErr := echeck.VerifyQuote(cert, quote); vErr == nil {
				qi := quote.GetQuoteInfo()
				gotSIGNER := fmt.Sprintf("%x", qi.MRSigner)
				if expectedMRSIGNER == "" || gotSIGNER == expectedMRSIGNER {
					copy(info.MRENCLAVE[:], qi.MREnclave[:])
					copy(info.MRSIGNER[:], qi.MRSigner[:])
				}
				// If MRSIGNER mismatched we deliberately leave
				// MRENCLAVE = zero so handleGet's allowlist check
				// rejects the caller. Don't fail the handshake —
				// break-glass-only endpoints might still want to
				// accept this cert.
			}
		}
		// No quote, or quote verification failed → leave MRENCLAVE
		// = zero. This is the operator-tool path: TLS terminates,
		// handleProvision/Delegate run, break-glass enforces auth.
		// handleGet will deny these callers.

		peers.put(certHash, info)
		return nil
	}
}

// connContext is the http.Server.ConnContext callback. Pulls the peer's
// leaf cert hash from the *tls.Conn, looks up the peerInfo we cached
// during the handshake, and attaches it to the request context.
func makeConnContext(peers *peerStore) func(ctx context.Context, c net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		tc, ok := c.(*tls.Conn)
		if !ok {
			return ctx
		}
		// HandshakeContext to ensure the handshake is done before we
		// inspect ConnectionState. http.Server's listener does this
		// before invoking ConnContext on the request, but we double-
		// check defensively.
		if err := tc.HandshakeContext(ctx); err != nil {
			return ctx
		}
		state := tc.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return ctx
		}
		hash := sha256.Sum256(state.PeerCertificates[0].Raw)
		info := peers.get(hash)
		if info == nil {
			return ctx
		}
		return withPeer(ctx, info)
	}
}
