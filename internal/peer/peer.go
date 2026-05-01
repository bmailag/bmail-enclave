// Package peer provides peer discovery and TLS certificate synchronization
// for SMTP enclaves. When multiple enclaves share the same hostname (e.g.,
// smtp.bmail.ag), they coordinate via DNS-based discovery to:
//
//   - Share TLS certificates so only one instance requests from Let's Encrypt
//   - Publish DANE/TLSA records via an attested API call
package peer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/tee"
)

// Config configures the PeerManager.
type Config struct {
	Hostname      string       // FQDN this enclave is responsible for (e.g., "smtp.bmail.ag")
	PeerPort      string       // Port for peer API (e.g., "8092")
	TEERuntime    tee.TEERuntime
	TLSKeyPath    string       // Sealed TLS key path
	CertDir       string       // Directory for Let's Encrypt cert cache
	DANEUpdateURL string       // e.g., "https://ws.atonline.com/_rest/Domain/Zone:daneUpdate"

	// AuthSecret gates /peer/key with HMAC-SHA256. Operator-provisioned via
	// PEER_AUTH_SECRET env var: a shared hex secret known only to sibling
	// peer enclaves. Requesters sign 'GET /peer/key\n<unix-timestamp>'; the
	// server verifies the MAC + rejects timestamps outside a ±60s window
	// to limit replay. Empty = endpoint refuses every request (fail closed).
	// Not as strong as full SGX attestation but closes the 'anyone on the
	// internal network can pull our TLS private key' gap.
	AuthSecret []byte
}

// Manager handles peer discovery, certificate synchronization, and DANE updates.
type Manager struct {
	cfg       Config
	mu        sync.RWMutex
	tlsCert   *tls.Certificate // Current TLS certificate
	tlsKey    []byte           // Raw private key bytes (for sharing with peers)
	certPEM   []byte           // PEM-encoded certificate chain
	spkiDER   []byte           // SPKI DER for TLSA computation
	localIPs  map[string]bool  // This host's IP addresses
}

// NewManager creates a new peer manager.
func NewManager(cfg Config) *Manager {
	if cfg.PeerPort == "" {
		cfg.PeerPort = "8092"
	}
	if cfg.DANEUpdateURL == "" {
		cfg.DANEUpdateURL = "https://ws.atonline.com/_rest/Domain/Zone:daneUpdate"
	}
	return &Manager{
		cfg:      cfg,
		localIPs: getLocalIPs(),
	}
}

// Start performs peer discovery, certificate synchronization, and DANE update.
// It should be called during enclave startup, after the TLS key is loaded.
func (m *Manager) Start(ctx context.Context, tlsCert *tls.Certificate, keyBytes []byte, spkiDER []byte) error {
	m.mu.Lock()
	m.tlsCert = tlsCert
	m.tlsKey = keyBytes
	m.spkiDER = spkiDER
	m.mu.Unlock()

	// Encode current cert as PEM for serving to peers.
	if tlsCert != nil && len(tlsCert.Certificate) > 0 {
		var buf bytes.Buffer
		for _, der := range tlsCert.Certificate {
			pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		m.mu.Lock()
		m.certPEM = buf.Bytes()
		m.mu.Unlock()
	}

	// Discover peers via DNS.
	peerIPs, err := m.discoverPeers(ctx)
	if err != nil {
		slog.Warn("peer discovery failed", "hostname", m.cfg.Hostname, "error", err)
	}

	// Try to get a cert from a peer if we don't have a Let's Encrypt one.
	if len(peerIPs) > 0 && !m.hasLECert() {
		for _, ip := range peerIPs {
			if err := m.syncFromPeer(ctx, ip); err != nil {
				slog.Warn("peer sync failed", "peer", ip, "error", err)
				continue
			}
			slog.Info("certificate synced from peer", "peer", ip)
			break
		}
	}

	// Update DANE TLSA record.
	if err := m.updateDANE(ctx); err != nil {
		slog.Warn("DANE TLSA update failed", "error", err)
	}

	return nil
}

// RegisterHandlers adds peer API endpoints to the given mux.
func (m *Manager) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /peer/cert", m.handleGetCert)
	mux.HandleFunc("GET /peer/key", m.handleGetKey)
	mux.HandleFunc("GET /peer/attestation", m.handleGetAttestation)
}

// TLSCert returns the current TLS certificate (may have been updated by peer sync).
func (m *Manager) TLSCert() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tlsCert
}

// discoverPeers resolves the hostname's DNS A records and returns peer IPs
// (excluding this host's own IPs). If this host's IP is not in the DNS
// results at all, we're not part of the pool and return an error.
func (m *Manager) discoverPeers(ctx context.Context) ([]string, error) {
	ips, err := net.DefaultResolver.LookupHost(ctx, m.cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", m.cfg.Hostname, err)
	}

	// Check if any of our local IPs appear in the DNS results.
	selfInPool := false
	for _, ip := range ips {
		if m.localIPs[ip] {
			selfInPool = true
			break
		}
	}
	if !selfInPool {
		slog.Warn("this host is not in the DNS pool, skipping peer discovery",
			"hostname", m.cfg.Hostname, "dns_ips", ips)
		return nil, nil
	}

	var peers []string
	for _, ip := range ips {
		if !m.localIPs[ip] {
			peers = append(peers, ip)
		}
	}

	slog.Info("peer discovery", "hostname", m.cfg.Hostname, "all_ips", ips, "peers", peers, "local_ips_count", len(m.localIPs))
	return peers, nil
}

// hasLECert checks whether the current cert is from Let's Encrypt (not self-signed).
func (m *Manager) hasLECert() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tlsCert == nil || m.tlsCert.Leaf == nil {
		return false
	}
	// Let's Encrypt certs have an issuer containing "Let's Encrypt" or "R3" / "R10" / "E5".
	issuer := m.tlsCert.Leaf.Issuer.CommonName
	return strings.Contains(issuer, "Let's Encrypt") ||
		strings.Contains(issuer, "R3") ||
		strings.Contains(issuer, "R10") ||
		strings.Contains(issuer, "E5") ||
		strings.Contains(issuer, "E6")
}

// syncFromPeer attempts to download a certificate and key from a peer.
func (m *Manager) syncFromPeer(ctx context.Context, peerIP string) error {
	peerURL := fmt.Sprintf("http://%s:%s", peerIP, m.cfg.PeerPort)
	client := &http.Client{Timeout: 10 * time.Second}

	// First check if the peer has a valid LE cert.
	certResp, err := client.Get(peerURL + "/peer/cert")
	if err != nil {
		return fmt.Errorf("get peer cert: %w", err)
	}
	defer certResp.Body.Close()
	if certResp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer cert status: %d", certResp.StatusCode)
	}

	certPEM, err := io.ReadAll(io.LimitReader(certResp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read peer cert: %w", err)
	}

	// Verify the peer's attestation.
	attestResp, err := client.Get(peerURL + "/peer/attestation")
	if err != nil {
		return fmt.Errorf("get peer attestation: %w", err)
	}
	defer attestResp.Body.Close()
	if attestResp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer attestation status: %d", attestResp.StatusCode)
	}

	var attestData struct {
		EnclaveID string `json:"enclave_id"`
		Quote     string `json:"quote"` // base64 SGX quote
	}
	if err := json.NewDecoder(attestResp.Body).Decode(&attestData); err != nil {
		return fmt.Errorf("decode attestation: %w", err)
	}
	// In production, verify the SGX quote here. In dev/sim mode, we accept any peer.
	slog.Info("peer attestation received", "peer", peerIP, "enclave_id", attestData.EnclaveID)

	// Request the private key. Signs a fresh timestamp with the shared
	// HMAC secret so the peer can verify us before handing over the key
	// (see handleGetKey). If AuthSecret isn't configured locally, the
	// request will be rejected by the peer anyway — don't even try.
	if len(m.cfg.AuthSecret) == 0 {
		return fmt.Errorf("peer auth secret not configured; cannot fetch key")
	}
	keyReq, err := http.NewRequest(http.MethodGet, peerURL+"/peer/key", nil)
	if err != nil {
		return fmt.Errorf("build peer key request: %w", err)
	}
	reqTS := time.Now().Unix()
	keyReq.Header.Set("X-Peer-Auth-Ts", strconv.FormatInt(reqTS, 10))
	keyReq.Header.Set("X-Peer-Auth", signPeerKeyRequest(m.cfg.AuthSecret, reqTS))
	keyResp, err := client.Do(keyReq)
	if err != nil {
		return fmt.Errorf("get peer key: %w", err)
	}
	defer keyResp.Body.Close()
	if keyResp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer key status: %d", keyResp.StatusCode)
	}

	keyPEM, err := io.ReadAll(io.LimitReader(keyResp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read peer key: %w", err)
	}

	// Parse and install the certificate.
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse peer cert+key: %w", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse peer leaf: %w", err)
	}
	tlsCert.Leaf = leaf

	// Re-seal the key locally.
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock != nil {
		sealed, err := m.cfg.TEERuntime.Seal(keyBlock.Bytes)
		if err != nil {
			slog.Warn("failed to re-seal peer key", "error", err)
		} else if err := os.WriteFile(m.cfg.TLSKeyPath, sealed, 0600); err != nil {
			slog.Warn("failed to persist re-sealed key", "error", err)
		} else {
			slog.Info("peer key re-sealed and persisted", "path", m.cfg.TLSKeyPath)
		}
	}

	// Update our state.
	m.mu.Lock()
	m.tlsCert = &tlsCert
	m.certPEM = certPEM
	m.tlsKey = keyBlock.Bytes
	m.spkiDER = leaf.RawSubjectPublicKeyInfo
	m.mu.Unlock()

	return nil
}

// updateDANE publishes the TLSA record via the DANE update API with SGX attestation.
func (m *Manager) updateDANE(ctx context.Context) error {
	m.mu.RLock()
	spki := m.spkiDER
	m.mu.RUnlock()

	if len(spki) == 0 {
		return fmt.Errorf("no SPKI available for DANE update")
	}

	// TLSA: Usage=3 (DANE-EE), Selector=1 (SPKI), MatchType=1 (SHA-256)
	hash := sha256.Sum256(spki)
	tlsaValue := fmt.Sprintf("3 1 1 %s", hex.EncodeToString(hash[:]))

	// Generate attestation binding the SPKI hash to this enclave.
	// We attest the raw 32-byte hash (not the full TLSA string) to stay
	// within the SGX report userData limit (64 bytes).
	quote, err := m.cfg.TEERuntime.Attest(hash[:])
	if err != nil {
		return fmt.Errorf("attest TLSA: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"host":        m.cfg.Hostname,
		"tlsa":        tlsaValue,
		"attestation": base64.StdEncoding.EncodeToString(quote),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.DANEUpdateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create DANE request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("DANE update request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("DANE update failed: %d %s", resp.StatusCode, string(respBody))
	}

	slog.Info("DANE TLSA record updated", "host", m.cfg.Hostname, "tlsa", tlsaValue)
	return nil
}

// ── Peer API Handlers ───────────────────────────────────────────────────────

// handleGetCert serves the current TLS certificate chain as PEM.
func (m *Manager) handleGetCert(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	certPEM := m.certPEM
	m.mu.RUnlock()

	if len(certPEM) == 0 {
		http.Error(w, "no certificate available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certPEM)
}

// peerKeyAuthSkew is the tolerance (each side) for client-vs-server clock
// drift when validating the signed timestamp in /peer/key requests.
const peerKeyAuthSkew = 60 * time.Second

// signPeerKeyRequest returns the HMAC-SHA256 MAC of
// 'GET /peer/key\n<unix-timestamp>' hex-encoded. Clients put the result
// in X-Peer-Auth; the server recomputes and compares with subtle.
func signPeerKeyRequest(secret []byte, unixTS int64) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("GET /peer/key\n"))
	mac.Write([]byte(fmt.Sprintf("%d", unixTS)))
	return hex.EncodeToString(mac.Sum(nil))
}

// handleGetKey serves the TLS private key as PEM after verifying an
// HMAC-authenticated request. The MAC covers the current unix timestamp
// so every request is unique; a replay is rejected once it's outside the
// ±peerKeyAuthSkew window.
func (m *Manager) handleGetKey(w http.ResponseWriter, r *http.Request) {
	if len(m.cfg.AuthSecret) == 0 {
		http.Error(w, "peer auth not configured", http.StatusServiceUnavailable)
		return
	}
	tsStr := r.Header.Get("X-Peer-Auth-Ts")
	mac := r.Header.Get("X-Peer-Auth")
	if tsStr == "" || mac == "" {
		http.Error(w, "missing peer auth headers", http.StatusUnauthorized)
		return
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid timestamp", http.StatusUnauthorized)
		return
	}
	now := time.Now().Unix()
	if ts < now-int64(peerKeyAuthSkew.Seconds()) || ts > now+int64(peerKeyAuthSkew.Seconds()) {
		http.Error(w, "timestamp outside acceptable window", http.StatusUnauthorized)
		return
	}
	expected := signPeerKeyRequest(m.cfg.AuthSecret, ts)
	providedBytes, err := hex.DecodeString(mac)
	if err != nil {
		http.Error(w, "invalid auth header", http.StatusUnauthorized)
		return
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(providedBytes, expectedBytes) {
		http.Error(w, "auth check failed", http.StatusForbidden)
		return
	}

	m.mu.RLock()
	keyBytes := m.tlsKey
	m.mu.RUnlock()

	if len(keyBytes) == 0 {
		http.Error(w, "no key available", http.StatusNotFound)
		return
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(keyPEM)
}

// handleGetAttestation serves this enclave's attestation info.
func (m *Manager) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	spki := m.spkiDER
	m.mu.RUnlock()

	quote, err := m.cfg.TEERuntime.Attest(spki)
	if err != nil {
		http.Error(w, "attestation failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"enclave_id": m.cfg.TEERuntime.SelfID(),
		"quote":      base64.StdEncoding.EncodeToString(quote),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// getLocalIPs returns all non-loopback IP addresses on this host.
func getLocalIPs() map[string]bool {
	ips := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips[ipnet.IP.String()] = true
		}
	}
	return ips
}
