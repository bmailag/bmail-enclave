package smtp

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	gosmtp "net/smtp"
	"net/textproto"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	vpCrypto "github.com/bmailag/bmail/internal/crypto"
	"github.com/bmailag/bmail/internal/domain"
	"github.com/bmailag/bmail/internal/storage"
	"github.com/bmailag/bmail/internal/tee"
)

// DKIMPoolKeys carries the parsed pool DKIM keys for one selector.
// Returned by a DKIMPoolGetter; smtp-outbound holds the result in
// RAM for the lifetime of the process (re-fetches on key rotation
// signal, TBD).
//
// Mirror of internal/keystore.DKIMPoolEntry's *private* halves, but
// kept independent here to avoid an import cycle and to let callers
// adapt other key stores in tests.
type DKIMPoolKeys struct {
	Selector    string
	Ed25519Seed []byte // 32 bytes
	RSAPKCS8    []byte // PKCS8 DER
}

// DKIMPoolGetter resolves a selector → pool keys. Implementations
// typically wrap a keystore.Client.Get + UnmarshalDKIMPoolEntry,
// possibly with caching. nil means smtp-outbound has no pool path
// and falls back exclusively to the legacy per-tenant unseal.
type DKIMPoolGetter func(ctx context.Context, selector string) (*DKIMPoolKeys, error)

// SMTPSender handles outbound email delivery with DKIM signing.
type SMTPSender struct {
	domainStore  *storage.DomainStore
	authStore    *storage.AuthStore // optional; for Autocrypt header injection
	redis        *redis.Client      // optional; nil disables MTA-STS caching
	teeRuntime   tee.TEERuntime     // for unsealing legacy per-tenant DKIM keys
	dkimPool     DKIMPoolGetter     // optional; non-nil enables ADR-007 pool path
	heloHostname string             // EHLO hostname (defaults to "smtp-out.bmail.ag")
}

// SMTPSenderOption configures optional dependencies for SMTPSender.
type SMTPSenderOption func(*SMTPSender)

// WithRedis sets a Redis client for caching MTA-STS policies.
func WithRedis(r *redis.Client) SMTPSenderOption {
	return func(s *SMTPSender) { s.redis = r }
}

// WithTEERuntime sets the TEE runtime for unsealing DKIM private keys.
func WithTEERuntime(rt tee.TEERuntime) SMTPSenderOption {
	return func(s *SMTPSender) { s.teeRuntime = rt }
}

// WithAuthStore sets an auth store for Autocrypt header injection.
func WithAuthStore(a *storage.AuthStore) SMTPSenderOption {
	return func(s *SMTPSender) { s.authStore = a }
}

// WithHeloHostname sets the EHLO hostname used in outbound SMTP connections.
func WithHeloHostname(h string) SMTPSenderOption {
	return func(s *SMTPSender) { s.heloHostname = h }
}

// WithDKIMPool wires a pool-key getter (typically backed by the
// keystore enclave, per ADR-007). When set, tenants with a non-empty
// DKIMPoolSelector are signed with the pool's keys; tenants with the
// flag empty stay on the legacy per-tenant unseal path.
func WithDKIMPool(g DKIMPoolGetter) SMTPSenderOption {
	return func(s *SMTPSender) { s.dkimPool = g }
}

// NewSMTPSender creates a new SMTPSender.
func NewSMTPSender(ds *storage.DomainStore, opts ...SMTPSenderOption) *SMTPSender {
	s := &SMTPSender{domainStore: ds, heloHostname: "smtp-out.bmail.ag"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ErrPermanent indicates a permanent delivery failure (5xx).
type ErrPermanent struct {
	Code    int
	Message string
}

func (e *ErrPermanent) Error() string {
	return fmt.Sprintf("permanent failure %d: %s", e.Code, e.Message)
}

// ErrTemporary indicates a temporary delivery failure (4xx).
type ErrTemporary struct {
	Code    int
	Message string
}

func (e *ErrTemporary) Error() string {
	return fmt.Sprintf("temporary failure %d: %s", e.Code, e.Message)
}

// SendMessage sends an email with DKIM signing via the recipient's MX server.
func (s *SMTPSender) SendMessage(ctx context.Context, from, to string, body []byte, tenantID uuid.UUID) error {
	// 1. Look up tenant to get DKIM key.
	tenant, err := s.domainStore.GetTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("lookup tenant: %w", err)
	}

	// 2a. Inject Autocrypt header if sender has a PGP public key.
	// This must happen before DKIM signing so the header is covered by the signature.
	if s.authStore != nil {
		pgpKey, err := s.authStore.GetPGPPublicKeyByAddress(ctx, from)
		if err == nil && pgpKey != "" {
			// Export minimal binary key and base64-encode for Autocrypt.
			minimalKey, exportErr := vpCrypto.ExportPGPPublicKeyMinimal(pgpKey)
			if exportErr == nil && len(minimalKey) > 0 {
				keyBase64 := base64.StdEncoding.EncodeToString(minimalKey)
				autocryptHeader := vpCrypto.FormatAutocryptHeader(from, keyBase64)
				// Insert Autocrypt header after the first line (before body).
				if idx := strings.Index(string(body), "\r\n"); idx >= 0 {
					body = append(body[:idx+2], append([]byte("Autocrypt: "+autocryptHeader+"\r\n"), body[idx+2:]...)...)
				}
			}
		}
	}

	// 2b. DKIM-sign the message. Two paths exist during the
	// per-tenant → keystore-pool migration (ADR-007):
	//   - tenant.DKIMPoolSelector set + s.dkimPool wired: signs with
	//     pool keys fetched from the keystore enclave. d= header is
	//     still tenant.Domain; receivers follow the CNAME from
	//     <selector>._domainkey.<tenant.Domain> to the pool's TXT.
	//   - otherwise: legacy per-tenant unseal path.
	// Try RSA first (universal support), then Ed25519. H4 fix tracks
	// whether at least one signature succeeded.
	dkimSigned := false

	usePool := tenant.DKIMPoolSelector != "" && s.dkimPool != nil
	var pool *DKIMPoolKeys
	if usePool {
		var err error
		pool, err = s.dkimPool(ctx, tenant.DKIMPoolSelector)
		if err != nil {
			return fmt.Errorf("fetch dkim pool %q: %w", tenant.DKIMPoolSelector, err)
		}
		if pool == nil {
			return fmt.Errorf("dkim pool getter returned nil for selector %q", tenant.DKIMPoolSelector)
		}
	}

	// RSA signature — preferred for compatibility with all receivers.
	if usePool {
		parsedKey, parseErr := x509.ParsePKCS8PrivateKey(pool.RSAPKCS8)
		if parseErr != nil {
			return fmt.Errorf("parse pool rsa pkcs8: %w", parseErr)
		}
		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("pool rsa key wrong type %T", parsedKey)
		}
		signed, signErr := domain.SignMessageRSA(rsaKey, tenant.Domain, pool.Selector, body)
		if signErr != nil {
			return fmt.Errorf("dkim rsa sign (pool): %w", signErr)
		}
		body = signed
		dkimSigned = true
		slog.Info("dkim_signed", "type", "rsa", "source", "pool", "selector", pool.Selector)
	} else if len(tenant.DKIMRSAPrivateKeyEncrypted) > 0 && tenant.DKIMRSASelector != "" {
		var rsaKeyDER []byte
		if s.teeRuntime != nil {
			unsealed, unsealErr := s.teeRuntime.Unseal(tenant.DKIMRSAPrivateKeyEncrypted)
			if unsealErr != nil {
				return fmt.Errorf("unseal RSA DKIM key: %w", unsealErr)
			}
			rsaKeyDER = unsealed
		} else {
			rsaKeyDER = tenant.DKIMRSAPrivateKeyEncrypted
		}
		parsedKey, parseErr := x509.ParsePKCS8PrivateKey(rsaKeyDER)
		if parseErr != nil {
			slog.Error("parse RSA DKIM key failed", "error", parseErr)
		} else if rsaKey, ok := parsedKey.(*rsa.PrivateKey); ok {
			signed, signErr := domain.SignMessageRSA(rsaKey, tenant.Domain, tenant.DKIMRSASelector, body)
			if signErr != nil {
				return fmt.Errorf("dkim rsa sign: %w", signErr)
			}
			body = signed
			dkimSigned = true
			slog.Info("dkim_signed", "type", "rsa", "source", "tenant", "selector", tenant.DKIMRSASelector)
		}
	}

	// Ed25519 signature — added as secondary for forward compatibility.
	//
	// POOL PATH INTENTIONALLY SKIPS ED25519: the pool publishes ONE selector,
	// and putting two key types under one selector makes DKIM verification
	// undefined (RFC 6376 §3.6.2.2 — the verifier picks an arbitrary TXT
	// record, so the RSA signature randomly fails against the ed25519 key).
	// That was junking custom-domain mail at our own inbound filter and would
	// do the same at Gmail. Receivers that matter don't verify ed25519-DKIM
	// anyway; the per-tenant path below keeps it because it uses separate
	// selectors per algorithm.
	if !usePool && len(tenant.DKIMPrivateKeyEncrypted) > 0 && tenant.DKIMSelector != "" {
		var seed []byte
		if s.teeRuntime != nil {
			unsealed, unsealErr := s.teeRuntime.Unseal(tenant.DKIMPrivateKeyEncrypted)
			if unsealErr != nil {
				return fmt.Errorf("unseal DKIM key: %w", unsealErr)
			}
			seed = unsealed
		} else {
			seed = tenant.DKIMPrivateKeyEncrypted
		}
		var privKey ed25519.PrivateKey
		switch len(seed) {
		case ed25519.SeedSize: // 32 bytes — seed only, derive full key.
			privKey = ed25519.NewKeyFromSeed(seed)
		case ed25519.PrivateKeySize: // 64 bytes — full private key (seed + public key).
			privKey = ed25519.PrivateKey(seed)
		default:
			slog.Error("ed25519 DKIM key wrong size", "expected", "32 or 64", "got", len(seed))
		}
		if privKey != nil {
			signed, signErr := domain.SignMessage(privKey, tenant.Domain, tenant.DKIMSelector, body)
			if signErr != nil {
				return fmt.Errorf("dkim sign: %w", signErr)
			}
			body = signed
			dkimSigned = true
			slog.Info("dkim_signed", "type", "ed25519", "source", "tenant", "selector", tenant.DKIMSelector)
		}
	}

	// H4 fix: Refuse to send unsigned mail — require at least one DKIM signature.
	if !dkimSigned {
		return fmt.Errorf("no DKIM key available for tenant %s (domain %s): refusing to send unsigned", tenantID, tenant.Domain)
	}

	// 3. MX lookup for recipient domain.
	recipientDomain := to
	if idx := strings.LastIndex(to, "@"); idx >= 0 {
		recipientDomain = to[idx+1:]
	}

	lookupCtx, lookupCancel := context.WithTimeout(ctx, 10*time.Second)
	defer lookupCancel()
	resolver := &net.Resolver{}
	mxRecords, err := resolver.LookupMX(lookupCtx, recipientDomain)
	if err != nil {
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("MX lookup for %s: %v", recipientDomain, err)}
	}
	if len(mxRecords) == 0 {
		return &ErrPermanent{Code: 550, Message: fmt.Sprintf("no MX records for %s", recipientDomain)}
	}

	// 4. Check DANE/TLSA and MTA-STS policies for the recipient domain.
	tlsPolicy := s.lookupTLSPolicy(recipientDomain, mxRecords)

	// 5. Try MX hosts in preference order.
	var lastErr error
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		lastErr = s.deliverToMX(ctx, host, from, to, body, tlsPolicy)
		if lastErr == nil {
			return nil
		}
		// On permanent failure, don't try other MX hosts.
		if _, ok := lastErr.(*ErrPermanent); ok {
			return lastErr
		}
	}

	return lastErr
}

// verifyTLSA checks the peer certificate's SPKI hash against the expected TLSA hash.
func verifyTLSA(conn *tls.Conn, expectedHash []byte) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificate for DANE verification")
	}
	spkiHash := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(spkiHash[:], expectedHash) != 1 {
		return fmt.Errorf("DANE TLSA mismatch: certificate does not match published TLSA record")
	}
	return nil
}

// tlsRequirement describes the TLS policy for a given delivery.
type tlsRequirement struct {
	requireTLS bool                // must negotiate TLS or fail delivery
	tlsaHashes map[string][][]byte // host -> all expected SHA-256 of peer SPKI (DANE)
	stsPolicy  *domain.MTASTSPolicy // parsed MTA-STS policy, nil if absent
}

// lookupTLSPolicy checks DANE TLSA records and MTA-STS for a recipient domain.
func (s *SMTPSender) lookupTLSPolicy(recipientDomain string, mxRecords []*net.MX) *tlsRequirement {
	pol := &tlsRequirement{tlsaHashes: make(map[string][][]byte)}

	// Check DANE TLSA for each MX host using proper TLSA RRtype (52).
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		hashes, err := lookupTLSARecords(host)
		if err != nil {
			slog.Debug("TLSA lookup failed", "host", host, "error", err)
			continue
		}
		// Store ALL TLSA hashes to support key rotation
		// where a domain publishes multiple TLSA records simultaneously.
		if len(hashes) > 0 {
			pol.tlsaHashes[host] = hashes
			pol.requireTLS = true
		}
	}

	// Check MTA-STS: look for _mta-sts TXT record, then fetch policy.
	resolver := &net.Resolver{}
	stsCtx, stsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	stsTxts, err := resolver.LookupTXT(stsCtx, "_mta-sts."+recipientDomain)
	stsCancel()
	if err == nil {
		hasSTS := false
		for _, txt := range stsTxts {
			if strings.Contains(txt, "v=STSv1") {
				hasSTS = true
				break
			}
		}
		if hasSTS {
			stsPolicy := s.fetchMTASTSPolicy(recipientDomain)
			if stsPolicy != nil {
				pol.stsPolicy = stsPolicy
				if stsPolicy.Mode == "enforce" {
					pol.requireTLS = true
				}
			}
		}
	}

	return pol
}

// mtaSTSCacheKey returns the Redis key for a cached MTA-STS policy.
func mtaSTSCacheKey(domain string) string {
	return "mtasts:policy:" + domain
}

// fetchMTASTSPolicy fetches and parses the MTA-STS policy for a domain.
// If Redis is configured, cached policies are returned when available and
// freshly-fetched policies are stored with TTL = max_age from the policy.
// Returns nil if the policy cannot be fetched or parsed.
func (s *SMTPSender) fetchMTASTSPolicy(recipientDomain string) *domain.MTASTSPolicy {
	// Try Redis cache first.
	if s.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cached, err := s.redis.Get(ctx, mtaSTSCacheKey(recipientDomain)).Bytes()
		if err == nil {
			var policy domain.MTASTSPolicy
			if json.Unmarshal(cached, &policy) == nil {
				return &policy
			}
		}
	}

	// Fetch from the network (first-fetch is the MITM-vulnerable window).
	policy := fetchMTASTSPolicyHTTP(recipientDomain)
	if policy != nil {
		slog.Warn("MTA-STS: first-fetch policy (verify legitimacy)", "domain", recipientDomain, "mode", policy.Mode, "mx", policy.MX, "max_age", policy.MaxAge)
	}

	// Cache the result in Redis if available.
	if policy != nil && s.redis != nil {
		if data, err := json.Marshal(policy); err == nil {
			ttl := time.Duration(policy.MaxAge) * time.Second
			if ttl <= 0 {
				ttl = 24 * time.Hour // fallback if max_age is missing/zero
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.redis.Set(ctx, mtaSTSCacheKey(recipientDomain), data, ttl).Err(); err != nil {
				slog.Warn("MTA-STS: failed to cache policy in Redis", "domain", recipientDomain, "error", err)
			}
		}
	}

	return policy
}

// fetchMTASTSPolicyHTTP performs the actual HTTP fetch of an MTA-STS policy.
func fetchMTASTSPolicyHTTP(recipientDomain string) *domain.MTASTSPolicy {
	url := "https://mta-sts." + recipientDomain + "/.well-known/mta-sts.txt"
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			// Only follow redirects to the same host (security).
			if req.URL.Host != "mta-sts."+recipientDomain {
				return fmt.Errorf("redirect to different host rejected")
			}
			return nil
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		slog.Warn("MTA-STS: failed to fetch policy", "domain", recipientDomain, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Limit read to 64KB — policies are tiny.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	policy, err := domain.ParseMTASTSPolicy(string(body))
	if err != nil {
		slog.Warn("MTA-STS: invalid policy", "domain", recipientDomain, "error", err)
		return nil
	}
	return policy
}

// smtpPort is the port used for outbound SMTP connections.
// Overridden in tests to point at mock servers.
var smtpPort = "25"

// deliverToMX connects to a single MX host and delivers the message.
func (s *SMTPSender) deliverToMX(ctx context.Context, host, from, to string, body []byte, pol *tlsRequirement) error {
	addr := net.JoinHostPort(host, smtpPort)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	// Force IPv4 — many providers (Gmail, etc.) reject IPv6 without proper PTR/SPF setup.
	// IPv6 outbound requires PTR records and SPF for the IPv6 address, which most
	// deployments don't have configured. IPv4 is universally supported.
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("tcp4", addr)
	if err != nil {
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("connect to %s: %v", addr, err)}
	}

	// Set a hard deadline on the entire SMTP conversation to prevent hung
	// goroutines when a remote MTA stalls after accepting the connection.
	txnDeadline := time.Now().Add(90 * time.Second)
	if deadline.Before(txnDeadline) {
		txnDeadline = deadline
	}
	conn.SetDeadline(txnDeadline)

	client, err := gosmtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("smtp client for %s: %v", host, err)}
	}
	defer client.Close()

	// Identify ourselves with the proper EHLO hostname (not "localhost").
	if err := client.Hello(s.heloHostname); err != nil {
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("EHLO %s to %s: %v", s.heloHostname, host, err)}
	}

	// STARTTLS negotiation.
	// If the server advertises STARTTLS, we MUST use it and verify the cert.
	// No InsecureSkipVerify, no plaintext fallback after a failed handshake.
	// If the server doesn't advertise STARTTLS at all, delivery proceeds
	// without TLS (unless DANE/MTA-STS requires it).
	tlsEstablished := false
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return &ErrTemporary{Code: 450, Message: fmt.Sprintf("STARTTLS failed for %s: %v", host, err)}
		}
		tlsEstablished = true
	}

	// Enforce TLS policy: if DANE or MTA-STS requires TLS, fail without it.
	if pol.requireTLS && !tlsEstablished {
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("TLS required by policy for %s but not available", host)}
	}

	// DANE TLSA certificate verification.
	// Match against ALL published TLSA hashes for key rotation support.
	if expectedHashes, ok := pol.tlsaHashes[host]; ok && tlsEstablished {
		state, ok := client.TLSConnectionState()
		if !ok || len(state.PeerCertificates) == 0 {
			return &ErrTemporary{Code: 450, Message: fmt.Sprintf("DANE: no peer certificate from %s", host)}
		}
		spkiHash := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		matched := false
		for _, expected := range expectedHashes {
			if subtle.ConstantTimeCompare(spkiHash[:], expected) == 1 {
				matched = true
				break
			}
		}
		if !matched {
			return &ErrPermanent{Code: 550, Message: fmt.Sprintf("DANE: TLSA hash mismatch for %s", host)}
		}
	}

	// MTA-STS: verify MX hostname is in policy's allowed list.
	if pol.stsPolicy != nil && pol.stsPolicy.Mode == "enforce" {
		if !pol.stsPolicy.MatchesMX(host) {
			return &ErrPermanent{Code: 550, Message: fmt.Sprintf("MTA-STS: MX host %s not in policy", host)}
		}
	}

	// MAIL FROM
	if err := client.Mail(from); err != nil {
		return classifyError(err)
	}

	// RCPT TO
	if err := client.Rcpt(to); err != nil {
		return classifyError(err)
	}

	// DATA
	wc, err := client.Data()
	if err != nil {
		return classifyError(err)
	}

	if _, err := wc.Write(body); err != nil {
		wc.Close()
		return &ErrTemporary{Code: 450, Message: fmt.Sprintf("write data: %v", err)}
	}

	if err := wc.Close(); err != nil {
		return classifyError(err)
	}

	client.Quit()
	return nil
}

// lookupTLSARecords queries DNS for TLSA records (RRtype 52) at _25._tcp.<host>.
// Returns SHA-256 hashes from DANE-EE (usage 3), SPKI (selector 1), SHA-256 (match 1) records.
func lookupTLSARecords(host string) ([][]byte, error) {
	tlsaName := fmt.Sprintf("_25._tcp.%s.", host)
	m := new(mdns.Msg)
	m.SetQuestion(tlsaName, mdns.TypeTLSA)
	m.SetEdns0(4096, true) // DNSSEC OK

	c := new(mdns.Client)
	c.Timeout = 10 * time.Second

	// Use system resolver address; fall back to localhost:53.
	resolverAddr := net.JoinHostPort("", "53")
	conf, confErr := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if confErr == nil && len(conf.Servers) > 0 {
		resolverAddr = net.JoinHostPort(conf.Servers[0], conf.Port)
	}

	r, _, err := c.Exchange(m, resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("TLSA query %s: %w", tlsaName, err)
	}

	if !r.AuthenticatedData {
		slog.Debug("TLSA response not DNSSEC-authenticated, ignoring", "host", host)
		return nil, nil
	}

	var hashes [][]byte
	for _, ans := range r.Answer {
		tlsa, ok := ans.(*mdns.TLSA)
		if !ok {
			continue
		}
		// DANE-EE (3), SPKI (1), SHA-256 (1) — the only profile we support.
		if tlsa.Usage == 3 && tlsa.Selector == 1 && tlsa.MatchingType == 1 {
			hash, decErr := hex.DecodeString(tlsa.Certificate)
			if decErr == nil && len(hash) == 32 {
				hashes = append(hashes, hash)
			} else {
				slog.Warn("malformed TLSA certificate hash", "host", host, "error", decErr)
			}
		}
	}
	return hashes, nil
}

// classifyError examines an SMTP error and returns either ErrPermanent or ErrTemporary.
func classifyError(err error) error {
	if err == nil {
		return nil
	}
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		if tpErr.Code >= 500 && tpErr.Code < 600 {
			return &ErrPermanent{Code: tpErr.Code, Message: tpErr.Msg}
		}
		return &ErrTemporary{Code: tpErr.Code, Message: tpErr.Msg}
	}
	// Non-SMTP errors (network, DNS, TLS) are temporary by default.
	return &ErrTemporary{Code: 450, Message: err.Error()}
}
