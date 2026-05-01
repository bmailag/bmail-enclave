package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/dnsattest"
	"github.com/bmailag/bmail/internal/keystore"
	"github.com/bmailag/bmail/internal/smtp"
	"github.com/bmailag/bmail/internal/tee"
)

// dkimPoolWiring carries the runtime artifacts smtp-outbound needs
// for the keystore-backed DKIM pool path: a signing-time getter (used
// per outbound message) and a startup-time keystore client (used to
// publish the pool's TXT records via attested enclaveUpdate).
//
// Both can be nil when env config disables the pool path; callers
// must check before use.
type dkimPoolWiring struct {
	getter smtp.DKIMPoolGetter
	client *keystore.Client
}

// buildDKIMPoolWiring assembles the wiring from env vars + the
// smtp-outbound enclave's existing TLS cert. Returns a zero
// dkimPoolWiring (both fields nil) when env vars are unset — the
// caller then runs without the pool path.
//
// Required env vars when enabled:
//
//	KEYSTORE_ADDR           — host:port of the keystore RPC endpoint
//	KEYSTORE_MRENCLAVE_HEX  — 64-char hex MRENCLAVE the keystore must present
//
// The smtp-outbound enclave's existing TLS cert (already created by
// tee.GenerateServerTLSConfig at startup for serving DKIM API on
// :8093) doubles as the mTLS client identity to the keystore.
//
// Caching: pool entries are fetched on first signing-use per
// selector and kept in a sync.Map for the process lifetime. Pool
// rotation today requires an smtp-outbound restart; an explicit
// Refresh hook is a follow-up.
func buildDKIMPoolWiring(teeRuntime tee.TEERuntime, smtpHostname, sealedTLSPath string) (dkimPoolWiring, error) {
	addr := os.Getenv("KEYSTORE_ADDR")
	mreHex := os.Getenv("KEYSTORE_MRENCLAVE_HEX")
	if addr == "" && mreHex == "" {
		return dkimPoolWiring{}, nil
	}
	if addr == "" || mreHex == "" {
		return dkimPoolWiring{}, fmt.Errorf("KEYSTORE_ADDR and KEYSTORE_MRENCLAVE_HEX must both be set or both unset")
	}

	mreBytes, err := hex.DecodeString(mreHex)
	if err != nil {
		return dkimPoolWiring{}, fmt.Errorf("decode KEYSTORE_MRENCLAVE_HEX: %w", err)
	}
	if len(mreBytes) != 32 {
		return dkimPoolWiring{}, fmt.Errorf("KEYSTORE_MRENCLAVE_HEX must be 32 bytes / 64 hex chars, got %d", len(mreBytes))
	}
	var expectedMRENC [32]byte
	copy(expectedMRENC[:], mreBytes)

	// Reuse smtp-outbound's own attestation TLS cert as the mTLS
	// client cert. The keystore extracts the embedded SGX quote and
	// looks up MRENCLAVE on the role allowlist.
	tlsCfg, _, err := tee.GenerateServerTLSConfig(teeRuntime, smtpHostname, sealedTLSPath)
	if err != nil {
		return dkimPoolWiring{}, fmt.Errorf("build smtp-outbound TLS cert for keystore mTLS: %w", err)
	}
	if len(tlsCfg.Certificates) == 0 {
		return dkimPoolWiring{}, fmt.Errorf("tls config has no certificates")
	}
	clientCert := tlsCfg.Certificates[0]

	cli, err := keystore.NewClient(keystore.ClientConfig{
		ServerAddr:                addr,
		ExpectedKeystoreMRENCLAVE: expectedMRENC,
		ClientCert:                clientCert,
		Timeout:                   15 * time.Second,
	})
	if err != nil {
		return dkimPoolWiring{}, fmt.Errorf("build keystore client: %w", err)
	}

	cache := poolCache{m: make(map[string]*smtp.DKIMPoolKeys)}
	getter := func(ctx context.Context, selector string) (*smtp.DKIMPoolKeys, error) {
		if hit := cache.get(selector); hit != nil {
			return hit, nil
		}
		entry, err := fetchPoolEntry(ctx, cli, selector)
		if err != nil {
			return nil, err
		}
		keys := &smtp.DKIMPoolKeys{
			Selector:    entry.Selector,
			Ed25519Seed: entry.Ed25519Seed,
			RSAPKCS8:    entry.RSAPKCS8,
		}
		cache.set(selector, keys)
		slog.Info("dkim pool key fetched", "selector", selector, "role", keystore.DKIMPoolRoleName(selector))
		return keys, nil
	}
	return dkimPoolWiring{getter: getter, client: cli}, nil
}

// fetchPoolEntry does one keystore Get + Unmarshal. Used by both the
// signing-time getter (which extracts private halves) and the
// startup-time publisher (which extracts public halves for DNS).
func fetchPoolEntry(ctx context.Context, cli *keystore.Client, selector string) (*keystore.DKIMPoolEntry, error) {
	role := keystore.DKIMPoolRoleName(selector)
	resp, err := cli.Get(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("keystore Get %s: %w", role, err)
	}
	entry, err := keystore.UnmarshalDKIMPoolEntry(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("parse pool entry %s: %w", role, err)
	}
	return entry, nil
}

// publishDKIMPoolTXTs fetches each named active selector and
// publishes its DKIM TXT records under the pool zone via attested
// enclaveUpdate. Idempotent — safe to run on every smtp-outbound
// boot.
//
// Env config (all required to enable):
//
//	KEYSTORE_DKIM_POOL_SELECTORS — comma-separated active selectors (e.g. "s1" or "s1,s2")
//	KEYSTORE_DKIM_POOL_ZONE      — DNS zone the pool TXTs live under (e.g. "dkim.bmail.ag" prod, "dkim.fullxp.net" test)
//
// Either env unset → skip publication silently. We deliberately
// require an explicit zone (no production default) to prevent a
// fullxp-style box from accidentally publishing into bmail.ag if
// it inherits an env file from prod.
//
// Two TXTs go up per selector (one Ed25519 + one RSA) using
// ModeReplace + ModeAdd so we sweep any stale entries on the first
// call but preserve our own second call.
func publishDKIMPoolTXTs(ctx context.Context, w dkimPoolWiring, runtime tee.TEERuntime) {
	if w.client == nil {
		return
	}
	selRaw := os.Getenv("KEYSTORE_DKIM_POOL_SELECTORS")
	zone := os.Getenv("KEYSTORE_DKIM_POOL_ZONE")
	if selRaw == "" || zone == "" {
		return
	}
	updater := dnsattest.New(runtime, "")

	for _, sel := range strings.Split(selRaw, ",") {
		sel = strings.TrimSpace(sel)
		if sel == "" {
			continue
		}
		entry, err := fetchPoolEntry(ctx, w.client, sel)
		if err != nil {
			slog.Error("dkim pool publish: keystore Get failed", "selector", sel, "err", err)
			continue
		}
		records := entry.DKIMPoolDNSRecords(zone)
		for i, r := range records {
			mode := dnsattest.ModeAdd
			if i == 0 {
				mode = dnsattest.ModeReplace
			}
			if err := updater.Update(ctx, r.Name, "TXT", r.Value, mode, 300); err != nil {
				slog.Error("dkim pool publish: dnsattest Update failed",
					"selector", sel, "host", r.Name, "alg", r.Algorithm, "mode", mode, "err", err)
				continue
			}
			slog.Info("dkim pool TXT published",
				"selector", sel, "host", r.Name, "alg", r.Algorithm, "mode", mode)
		}
	}
}

// handlePreDeploy returns the localhost-only HTTP handler that the
// deploy script hits BEFORE replacing the smtp-outbound binary.
//
// Why: the keystore's role allowlist is bound to specific MRENCLAVE
// values. A code change drifts smtp-outbound's MRENCLAVE; the new
// binary boots, calls keystore Get, gets 403 ("caller not on
// allowlist"), and DKIM signing dies. The fix is "chained
// delegation" (per ADR-006): the OLD enclave, while still
// allowlisted, calls Delegate(role, new_mrenclave) so the new
// MRENCLAVE is allowlisted before its first boot.
//
// Auth model:
//   - Localhost-only (127.0.0.1 / ::1). The deploy script and the
//     enclave run on the same host, so this is the natural trust
//     boundary; anything else requires also accepting that the host
//     is compromised, which already loses.
//   - The actual delegation auth is the chained-allowlist check on
//     the keystore side: only an MRENCLAVE *currently* on the role's
//     allowlist can add another MRENCLAVE to it. So even a malicious
//     local process that hits this endpoint can only add an
//     MRENCLAVE — and only via this enclave's own attested mTLS
//     channel, which is gated by SGX.
//
// Body: {"new_mrenclave_hex": "<64 hex chars>"}.
// For each active pool selector (KEYSTORE_DKIM_POOL_SELECTORS),
// calls keystore.Client.Delegate(smtp-outbound-dkim-pool-<sel>,
// new_mrenclave). Reports per-role outcomes in the response.
func handlePreDeploy(wiring dkimPoolWiring) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != "127.0.0.1" && host != "::1" && host != "" {
			http.Error(w, "localhost only", http.StatusForbidden)
			return
		}
		if wiring.client == nil {
			http.Error(w, "keystore not configured (KEYSTORE_ADDR/KEYSTORE_MRENCLAVE_HEX unset)", http.StatusServiceUnavailable)
			return
		}

		var req struct {
			NewMRENCLAVEHex string `json:"new_mrenclave_hex"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		mreBytes, err := hex.DecodeString(req.NewMRENCLAVEHex)
		if err != nil || len(mreBytes) != 32 {
			http.Error(w, "new_mrenclave_hex must be 32 bytes / 64 hex chars", http.StatusBadRequest)
			return
		}
		var newMRE [32]byte
		copy(newMRE[:], mreBytes)

		selRaw := os.Getenv("KEYSTORE_DKIM_POOL_SELECTORS")
		if selRaw == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"delegated": []string{},
				"note":      "KEYSTORE_DKIM_POOL_SELECTORS empty — nothing to delegate",
			})
			return
		}

		type result struct {
			Role  string `json:"role"`
			Error string `json:"error,omitempty"`
		}
		results := []result{}
		anySuccess := false
		for _, sel := range strings.Split(selRaw, ",") {
			sel = strings.TrimSpace(sel)
			if sel == "" {
				continue
			}
			role := keystore.DKIMPoolRoleName(sel)
			res, derr := wiring.client.Delegate(r.Context(), role, newMRE)
			if derr != nil {
				slog.Error("pre-deploy delegate failed",
					"role", role, "new_mrenclave", req.NewMRENCLAVEHex, "err", derr)
				results = append(results, result{Role: string(role), Error: derr.Error()})
				continue
			}
			anySuccess = true
			slog.Info("pre-deploy delegate ok",
				"role", role, "new_mrenclave", req.NewMRENCLAVEHex,
				"allowed_count", len(res.AllowedMRENCLAVE))
			results = append(results, result{Role: string(role)})
		}

		status := http.StatusOK
		if !anySuccess {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]any{
			"new_mrenclave_hex": req.NewMRENCLAVEHex,
			"results":           results,
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// poolCache is a small concurrent map of selector → resolved keys.
// Lifetime is the process; a future Refresh hook can clear it.
type poolCache struct {
	mu sync.RWMutex
	m  map[string]*smtp.DKIMPoolKeys
}

func (c *poolCache) get(sel string) *smtp.DKIMPoolKeys {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.m[sel]
}

func (c *poolCache) set(sel string, keys *smtp.DKIMPoolKeys) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[sel] = keys
}
