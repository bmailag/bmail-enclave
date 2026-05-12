package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/tee"
)

// sgxQuotesProxy serves /.well-known/sgx-quotes/{name} by either
// invoking the gateway's local AttestationHandler (for name="gateway")
// or HTTP-proxying to whichever upstream URL was passed in for the
// other enclave names.
type sgxQuotesProxy struct {
	teeRuntime tee.TEERuntime
	upstreams  map[string]string // name -> URL (empty value disables that name)
	client     *http.Client
	// F-02b: identity key + live-TLS-pubkey closure for the local
	// "gateway" case. Passed through to AttestationHandlerWithIdentity
	// so the proxy's gateway response matches what /gateway/attestation
	// on the main mux returns (same REPORTDATA binding, same JSON).
	gatewayIdentityPub []byte
	gatewayTLSPubKeyFn func() []byte
}

func newSGXQuotesProxy(teeRuntime tee.TEERuntime, upstreams map[string]string) *sgxQuotesProxy {
	// Upstream attestation endpoints serve TLS with self-signed
	// per-enclave certs (e.g., payment's HTTPS listener uses a sealed
	// key with no CA chain). Skipping verification on this client is
	// safe because:
	//   1. The /attestation response is an SGX quote, which is
	//      independently signature-verifiable end-to-end (Intel root
	//      CA chain inside the report). TLS adds no security here.
	//   2. The proxy only fetches localhost / WireGuard-internal URLs
	//      — there's no cross-network trust boundary at this point.
	// Hardening to mutual SGX attestation between gateway and the
	// upstream enclaves would be an improvement; it's not in scope
	// for the /verify cross-check.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &sgxQuotesProxy{
		teeRuntime: teeRuntime,
		upstreams:  upstreams,
		client: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		},
	}
}

func (p *sgxQuotesProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.PathValue("name")
	// Defense-in-depth: clamp to a known set even though the mux pattern
	// gives us a single path segment. Anything outside the allowlist
	// goes 404 so we never proxy arbitrary names a typo could create.
	switch name {
	case "gateway":
		// Serve our own attestation locally. Same Plan-B binding shape
		// as the /gateway/attestation route: REPORTDATA = sha256(
		// identity_public_key); response also includes the current
		// autocert TLS pubkey via the closure for browser cross-check.
		gateway.AttestationHandlerWithIdentity(p.teeRuntime, p.gatewayIdentityPub, p.gatewayTLSPubKeyFn).ServeHTTP(w, r)
		return
	case "smtp-inbound", "smtp-outbound", "payment", "keystore":
		upstream := p.upstreams[name]
		if upstream == "" {
			// Configured-but-empty means the operator hasn't wired
			// this enclave's URL yet (typical in dev / fullxp). The
			// /verify page renders this row as "unavailable".
			http.Error(w, `{"error":"upstream not configured"}`, http.StatusServiceUnavailable)
			return
		}
		p.proxyTo(w, r, name, upstream)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

// proxyTo issues an HTTP GET against the upstream attestation URL and
// streams the response back. Errors collapse to a 502 with a short JSON
// body so the /verify page can surface a meaningful message.
func (p *sgxQuotesProxy) proxyTo(w http.ResponseWriter, r *http.Request, name, upstream string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		slog.Error("sgx-quotes: bad upstream url", "name", name, "url", upstream, "error", err)
		http.Error(w, `{"error":"bad upstream url"}`, http.StatusBadGateway)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		slog.Warn("sgx-quotes: upstream fetch failed", "name", name, "error", err)
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		slog.Warn("sgx-quotes: read upstream body failed", "name", name, "error", err)
		http.Error(w, `{"error":"upstream read failed"}`, http.StatusBadGateway)
		return
	}

	// Pass through the upstream's content-type if it looks like JSON;
	// otherwise enforce JSON ourselves so /verify can parse safely.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "json") {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")

	// Map upstream non-2xx into 502 so /verify treats it uniformly. The
	// upstream's body is preserved as-is (still a JSON error object).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.WriteHeader(http.StatusBadGateway)
		w.Write(body)
		return
	}

	// Successful upstream: rewrite to a small wrapper that names which
	// enclave the report came from. Pass the upstream JSON inline so
	// the browser doesn't need to parse a second layer.
	if json.Valid(body) {
		w.Write(body)
		return
	}
	// Defense: if the upstream returned non-JSON 2xx, surface as 502.
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(`{"error":"upstream returned non-JSON"}`))
}
