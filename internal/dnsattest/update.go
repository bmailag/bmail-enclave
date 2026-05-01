// Package dnsattest publishes DNS records via KLB's
// `Domain/Zone:enclaveUpdate` API with an SGX attestation that binds
// the running enclave to the exact (type, host, value) triple.
//
// Same trust model as the older daneUpdate endpoint: KLB validates
// the Intel quote chain, confirms quote.MRSIGNER matches bmail's
// signing identity, and confirms the embedded reportData matches
// SHA-256(type ":" host ":" value). Any bmail-signed enclave can
// publish records inside zones bmail owns — no per-MRENCLAVE
// allowlist needed because the offline-protected private.pem is
// already the binding constraint.
//
// Used by smtp-outbound to publish DKIM pool TXT records under the
// pool-zone selectors (ADR-007). Designed to also subsume
// smtp-inbound's TLSA publishing in a future refactor.
package dnsattest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bmailag/bmail/internal/tee"
)

// DefaultEndpoint is the production KLB enclaveUpdate URL. Tests can
// override per-Updater with WithEndpoint.
const DefaultEndpoint = "https://ws.atonline.com/_rest/Domain/Zone:enclaveUpdate"

// Mode names the three update behaviors KLB exposes:
//
//	ModeReplace — replace ALL records of (type, host) with this single value (default)
//	ModeAdd     — add this value alongside any existing records
//	ModeRemove  — remove a matching value, leaving others
const (
	ModeReplace = "replace"
	ModeAdd     = "add"
	ModeRemove  = "remove"
)

// Updater publishes attested DNS updates. Safe for concurrent use.
type Updater struct {
	runtime  tee.TEERuntime
	endpoint string
	httpc    *http.Client
}

// New constructs an Updater. runtime supplies the SGX quote;
// endpoint defaults to KLB's production URL when empty.
func New(runtime tee.TEERuntime, endpoint string) *Updater {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Updater{
		runtime:  runtime,
		endpoint: endpoint,
		httpc:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Update publishes one record. mode = ModeReplace is the safe
// default for first-time and re-publish flows; ModeAdd is for
// multi-value records (e.g. two DKIM TXTs under the same selector,
// one ed25519 + one rsa).
//
// ttl ≤ 0 → API default (300s).
//
// reportData binding: SHA-256("<type>:<host>:<value>") ties the
// quote to this exact triple. KLB rejects on any mismatch.
func (u *Updater) Update(ctx context.Context, host, recordType, value, mode string, ttl int) error {
	if u == nil || u.runtime == nil {
		return fmt.Errorf("dnsattest: updater not initialized")
	}
	if host == "" || recordType == "" || value == "" {
		return fmt.Errorf("dnsattest: host, type, value all required")
	}
	if mode == "" {
		mode = ModeReplace
	}

	bound := []byte(recordType + ":" + host + ":" + value)
	rd := sha256.Sum256(bound)

	quote, err := u.runtime.Attest(rd[:])
	if err != nil {
		return fmt.Errorf("dnsattest: attest %s %s: %w", recordType, host, err)
	}

	body, _ := json.Marshal(map[string]any{
		"host":        host,
		"type":        recordType,
		"value":       value,
		"mode":        mode,
		"ttl":         ttl,
		"attestation": base64.StdEncoding.EncodeToString(quote),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dnsattest: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("dnsattest: post %s: %w", u.endpoint, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dnsattest: %s %s/%s mode=%s: HTTP %d: %s",
			recordType, host, truncate(value, 32), mode, resp.StatusCode, truncate(string(respBody), 256))
	}

	// Decode the envelope so a "result":"error" with HTTP 200 (rare
	// but possible) doesn't slip through silently.
	var env struct {
		Result string `json:"result"`
		Error  string `json:"error"`
		Token  string `json:"token"`
	}
	_ = json.Unmarshal(respBody, &env)
	if env.Result != "" && env.Result != "success" {
		return fmt.Errorf("dnsattest: %s %s mode=%s: API error %s (token=%s)",
			recordType, host, mode, env.Error, env.Token)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
