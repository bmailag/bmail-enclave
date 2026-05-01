package keystore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KarpelesLab/echeck"
)

// Client is the consumer-side wrapper for talking to a Keystore enclave
// over mutual SGX-attested mTLS. Each consumer enclave (gateway, smtp-*,
// payment) creates one of these at startup and uses it to fetch its
// long-lived keys via Get().
//
// Auth (mutual):
//   - Client presents its own attestation cert (the same one its TLS
//     server hands to gateway / external callers — built by
//     tee.GenerateServerTLSConfig). The keystore validates the embedded
//     SGX quote, extracts MRENCLAVE, looks it up in the per-role
//     allowlist.
//   - Server presents the keystore's own attestation cert. We verify
//     the embedded SGX quote and confirm its MRENCLAVE matches the
//     value pinned by the operator (`expectedKeystoreMRENCLAVE`). This
//     prevents man-in-the-middle by another bmail-signed enclave.
//
// Network address (`serverAddr`) is internal-only — typically
// "127.0.0.1:8094" when keystore is co-located, or the WireGuard IP
// when separated. Don't expose publicly.
type Client struct {
	serverAddr string
	httpc      *http.Client
}

// ClientConfig captures the small set of things a consumer needs to
// dial the keystore. Caller is responsible for getting the
// expectedKeystoreMRENCLAVE out of band — typically baked in at build
// time or read from a sealed/operator-signed config file. NEVER trust
// it from a network-supplied source.
type ClientConfig struct {
	// ServerAddr is host:port of the keystore RPC endpoint.
	ServerAddr string

	// ExpectedKeystoreMRENCLAVE is the 32-byte hash the keystore's
	// presented attestation cert MUST encode. Consumers refuse to talk
	// to anything else.
	ExpectedKeystoreMRENCLAVE [32]byte

	// ClientCert is the consumer's own attestation cert (with embedded
	// SGX quote). Built by tee.GenerateServerTLSConfig at startup.
	// Reused as the client cert for mTLS to the keystore.
	ClientCert tls.Certificate

	// Timeout caps the round-trip for each RPC. 30s is generous for
	// what should be sub-millisecond RPCs.
	Timeout time.Duration
}

// NewClient builds the HTTP client. Validates the configuration; does
// NOT make any network call yet.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ServerAddr == "" {
		return nil, errors.New("keystore-client: ServerAddr required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	expected := cfg.ExpectedKeystoreMRENCLAVE

	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("keystore-client: server presented no cert")
		}
		serverCert := cs.PeerCertificates[0]

		// Empty expected = sim/dev mode, skip SGX validation. Production
		// must always have it set.
		var zero [32]byte
		if expected == zero {
			return nil
		}

		quote, err := echeck.ExtractQuote(serverCert)
		if err != nil {
			return fmt.Errorf("keystore-client: extract server quote: %w", err)
		}
		if err := echeck.VerifyQuote(serverCert, quote); err != nil {
			return fmt.Errorf("keystore-client: server quote verify: %w", err)
		}
		info := quote.GetQuoteInfo()
		var got [32]byte
		copy(got[:], info.MREnclave[:])
		if got != expected {
			return fmt.Errorf("keystore-client: server MRENCLAVE mismatch: got %x, want %x", got, expected)
		}
		return nil
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cfg.ClientCert},
		InsecureSkipVerify: true, // we verify the SGX quote, not a CA chain
		VerifyConnection:   verify,
	}

	return &Client{
		serverAddr: cfg.ServerAddr,
		httpc: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Get fetches the key material for the role.
func (c *Client) Get(ctx context.Context, role Role) (*GetResponse, error) {
	var resp GetResponse
	if err := c.do(ctx, "/keystore/get", GetRequest{Role: role}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Delegate adds a new MRENCLAVE to the role's allowlist via chained
// delegation. The caller must be on the role's current allowlist. For
// initial bootstrap or break-glass, set BreakGlass on the request via
// DelegateWithBreakGlass.
func (c *Client) Delegate(ctx context.Context, role Role, newMRENCLAVE [32]byte) (*DelegateResponse, error) {
	var resp DelegateResponse
	if err := c.do(ctx, "/keystore/delegate", DelegateRequest{Role: role, NewMRENCLAVE: newMRENCLAVE}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DelegateWithBreakGlass is the operator path: signed by the offline
// operator credential, no requirement that the caller be on any
// allowlist.
func (c *Client) DelegateWithBreakGlass(ctx context.Context, role Role, newMRENCLAVE [32]byte, bg BreakGlassProof) (*DelegateResponse, error) {
	var resp DelegateResponse
	req := DelegateRequest{Role: role, NewMRENCLAVE: newMRENCLAVE, BreakGlass: &bg}
	if err := c.do(ctx, "/keystore/delegate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Provision installs the FIRST key for a role. Always requires
// break-glass — there's no "consumer self-provisions" path.
func (c *Client) Provision(ctx context.Context, role Role, key []byte, keyType string, bg BreakGlassProof) (*ProvisionResponse, error) {
	var resp ProvisionResponse
	req := ProvisionRequest{Role: role, Key: key, KeyType: keyType, BreakGlass: bg}
	if err := c.do(ctx, "/keystore/provision", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Revoke removes an MRENCLAVE from a role's allowlist. Break-glass-only.
func (c *Client) Revoke(ctx context.Context, role Role, oldMRENCLAVE [32]byte, bg BreakGlassProof) error {
	req := RevokeRequest{Role: role, OldMRENCLAVE: oldMRENCLAVE, BreakGlass: bg}
	return c.do(ctx, "/keystore/revoke", req, nil)
}

// List dumps roles + allowlists + audit tail. Break-glass-only.
func (c *Client) List(ctx context.Context, auditTailSize int, bg BreakGlassProof) (*ListResponse, error) {
	var resp ListResponse
	req := ListRequest{BreakGlass: bg, AuditTailSize: auditTailSize}
	if err := c.do(ctx, "/keystore/list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// do is the shared request/response cycle.
func (c *Client) do(ctx context.Context, path string, body any, out any) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	url := "https://" + c.serverAddr + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("keystore round-trip: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		// Server-side errors are JSON envelopes with an "error" key.
		var env struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &env)
		return fmt.Errorf("keystore %s %s: status %d: %s", req.Method, path, resp.StatusCode, env.Error)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

