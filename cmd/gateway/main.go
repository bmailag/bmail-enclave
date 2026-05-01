// Package main implements the SGX gateway enclave — the privacy-preserving
// entry point for all client connections. Per Paper 3, this enclave:
//
//   - Terminates TLS directly (no nginx) so client IPs never leave enclave memory
//   - Strips all client-identifying headers before forwarding to the backend
//   - Serves static frontend files
//   - Proxies external image/resource fetches for authenticated users
//   - Rate limits by H(IP || salt) using a count-min sketch (no IP persistence)
//
// The enclave code surface is intentionally minimal for reproducible builds.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/bmailag/bmail/internal/gateway"
	"github.com/bmailag/bmail/internal/tee"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("gateway: %v", err)
	}
}

func run() error {
	slog.Info("starting gateway enclave", "version", "2.0")

	// ── Configuration ───────────────────────────────────────────────────

	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://127.0.0.1:8082"
	}
	backend, err := url.Parse(backendURL)
	if err != nil {
		return fmt.Errorf("parse BACKEND_URL: %w", err)
	}

	webRoot := os.Getenv("WEB_ROOT")
	if webRoot == "" {
		webRoot = "/var/www/bmail"
	}

	// Domains for Let's Encrypt certificates.
	domainsStr := os.Getenv("GATEWAY_DOMAINS")
	var domains []string
	if domainsStr != "" {
		for _, d := range strings.Split(domainsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domains = append(domains, d)
				allowedDomainSet[d] = true
			}
		}
	}

	certDir := os.Getenv("CERT_CACHE_DIR")
	if certDir == "" {
		certDir = "/opt/bmail/certs"
	}

	// Rate limit: requests per IP per minute.
	rateLimit := 120
	if v := os.Getenv("RATE_LIMIT"); v != "" {
		fmt.Sscanf(v, "%d", &rateLimit)
	}

	// ── TEE Runtime ─────────────────────────────────────────────────────

	teeRuntime := tee.NewRuntime()
	slog.Info("TEE runtime", "id", teeRuntime.SelfID())

	// ── Rate Limiter (privacy-preserving, IP-based) ─────────────────────

	limiter := newIPRateLimiter(rateLimit, time.Minute)
	// Two-tier IP cap on register/finish:
	//   - regLimiter:      5 attempts per minute (burst — covers
	//                      fat-finger retries within seconds)
	//   - regDailyLimiter: 2 attempts per 24h (sustained — caps
	//                      drip-style multi-account abuse from a
	//                      single IP). Both must pass.
	regLimiter := newIPRateLimiter(5, time.Minute)
	regDailyLimiter := newIPRateLimiter(2, 24*time.Hour)

	// ── Reverse Proxy to Backend ────────────────────────────────────────

	apiProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backend.Scheme
			req.URL.Host = backend.Host
			// Normalize to backend-facing path. Three URL spaces route through
			// this proxy; the backend sees only the stripped form so existing
			// handlers continue to work unchanged, while /fakeid/ requests
			// retain their /fakeid/ prefix so backend middleware can recognize
			// them via IsFakeIDPath.
			//   /app/api/auth/login    → /auth/login        (primary)
			//   /fakeid/api/auth/login → /fakeid/auth/login (fake id)
			//   /api/auth/login        → /auth/login        (legacy)
			req.URL.Path = gatewayBackendPath(req.URL.Path)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}

			// CRITICAL: Strip all client-identifying headers (Paper 3, Property 1).
			// Only forward what the backend needs.
			sanitized := make(http.Header)
			// Preserve cookies (session auth).
			if c := req.Header.Get("Cookie"); c != "" {
				sanitized.Set("Cookie", c)
			}
			sanitized.Set("Content-Type", req.Header.Get("Content-Type"))
			sanitized.Set("Content-Length", req.Header.Get("Content-Length"))
			sanitized.Set("Accept", req.Header.Get("Accept"))
			if v := req.Header.Get("X-Csrf-Token"); v != "" {
				sanitized.Set("X-Csrf-Token", v)
			}
			if v := req.Header.Get("X-Request-Id"); v != "" {
				sanitized.Set("X-Request-Id", v)
			}
			if v := req.Header.Get("X-Client-Type"); v != "" {
				sanitized.Set("X-Client-Type", v)
			}
			if v := req.Header.Get("X-Account-Index"); v != "" {
				sanitized.Set("X-Account-Index", v)
			}
			if v := req.Header.Get("Last-Event-Id"); v != "" {
				sanitized.Set("Last-Event-Id", v)
			}
			if v := req.Header.Get("Authorization"); v != "" {
				sanitized.Set("Authorization", v)
			}
			if v := req.Header.Get("Cache-Control"); v != "" {
				sanitized.Set("Cache-Control", v)
			}
			if v := req.Header.Get("If-None-Match"); v != "" {
				sanitized.Set("If-None-Match", v)
			}
			// Stripe webhook signature (allowed through for /billing/webhook).
			if v := req.Header.Get("Stripe-Signature"); v != "" {
				sanitized.Set("Stripe-Signature", v)
			}
			// Forwarded host for multi-domain support.
			sanitized.Set("X-Forwarded-Host", req.Host)

			req.Header = sanitized
			req.Host = backend.Host
		},
		FlushInterval: -1, // Stream SSE responses immediately.
		ErrorLog:      log.New(io.Discard, "", 0),
	}

	// ── Image/Resource Proxy ────────────────────────────────────────────

	imageProxy := newImageProxyHandler()

	// ── Static File Server ──────────────────────────────────────────────

	staticFS := http.FileServer(http.Dir(webRoot))

	// ── Router ──────────────────────────────────────────────────────────

	// Rate-limited paths. Keys are the *backend-facing* path (post
	// gatewayBackendPath normalization), so a single entry covers
	// /app/api/auth/login, /fakeid/api/auth/login, and /api/auth/login
	// (which rewrite to /auth/login, /fakeid/auth/login, /auth/login
	// respectively). Fake ID variants are listed explicitly where they
	// have distinct Fake ID-only endpoints.
	rateLimitedPaths := map[string]bool{
		"/auth/login/start":             true,
		"/auth/login/finish":            true,
		"/auth/register/start":          true,
		"/auth/register/finish":         true,
		"/auth/recover/start":           true,
		"/auth/recover/finish":          true,
		"/auth/recover/email":           true,
		"/auth/recover/opaque/start":    true,
		"/auth/recover/opaque/ke3":      true,
		"/auth/login/verify-totp":       true,
		"/fakeid/auth/login/start":      true,
		"/fakeid/auth/login/finish":     true,
		"/fakeid/auth/register/start":   true,
		"/fakeid/auth/register/finish":  true,
		"/fakeid/auth/recover/start":    true,
		"/fakeid/auth/recover/finish":   true,
	}

	// Public API paths that don't require credentials (backend-facing).
	publicPaths := map[string]bool{
		"/auth/domains":             true,
		"/auth/turnstile-config":    true,
		"/auth/login/start":         true,
		"/auth/login/finish":        true,
		"/auth/login/verify-totp":   true,
		"/auth/register/start":      true,
		"/auth/register/finish":     true,
		"/auth/register/invite/start":  true,
		"/auth/register/invite/finish": true,
		"/auth/recover/start":         true,
		"/auth/recover/finish":        true,
		"/auth/recover/email":         true,
		"/auth/recover/email/start":   true,
		"/auth/recover/opaque/start":  true,
		"/auth/recover/opaque/ke3":    true,
		"/auth/refresh":               true,
		"/auth/accounts":              true,
		"/auth/push-config":           true,
		"/auth/keys":                  true,
		"/auth/recipient-keys":        true,
		"/auth/pgp-key":               true,
		"/auth/verify-backup-email":   true,
		"/billing/webhook":            true,
		"/affiliate/track":            true,
		"/spec":                       true,
		// Fake ID public endpoints — registration/login/recovery are
		// unauthenticated; only the minting step at the primary side
		// is gated (that happens at /app/api/fakeid/mint with an
		// authenticated primary cookie).
		"/fakeid/auth/login/start":    true,
		"/fakeid/auth/login/finish":   true,
		"/fakeid/auth/register/start":  true,
		"/fakeid/auth/register/finish": true,
		"/fakeid/auth/recover/start":  true,
		"/fakeid/auth/recover/finish": true,
		"/fakeid/auth/refresh":        true,
		"/fakeid/auth/keys":           true,
	}

	// hasCredentials checks if the request has any bmail session cookie or
	// Authorization header. Recognizes three cookie families:
	//
	//   bmail_session / bmail_session_N → primary account sessions (Path=/app/)
	//   bmail_fakeid_session            → fake id sessions        (Path=/fakeid/)
	//   (legacy bmail_session with no path) → migration-era primary sessions
	//
	// The earlier implementation only matched HasPrefix(c.Name, "bmail_session")
	// which did not match "bmail_fakeid_session" because the prefix "bmail_session"
	// diverges from "bmail_fakeid" at character 6. A Fake ID user with valid
	// cookies would be 401'd at the gateway before the backend ever saw the
	// request.
	hasCredentials := func(r *http.Request) bool {
		for _, c := range r.Cookies() {
			if strings.HasPrefix(c.Name, "bmail_session") || strings.HasPrefix(c.Name, "bmail_fakeid_session") {
				return true
			}
		}
		return r.Header.Get("Authorization") != ""
	}

	mux := http.NewServeMux()

	// Paths with a stricter registration rate limit (5/min per IP).
	// Keys are backend-facing (post gatewayBackendPath).
	regLimitedPaths := map[string]bool{
		"/auth/register/finish":        true,
		"/auth/register/invite/finish": true,
		"/fakeid/auth/register/finish": true,
	}

	// Shared API handler. Serves /api/*, /app/api/*, /fakeid/api/*.
	// All three prefixes normalize to the backend-facing path via
	// gatewayBackendPath before rate/auth checks; the reverse-proxy
	// director re-applies the same normalization when talking to the
	// backend so it sees exactly one canonical path space.
	apiHandler := func(w http.ResponseWriter, r *http.Request) {
		bp := gatewayBackendPath(r.URL.Path)

		// Rate limit auth-sensitive endpoints by IP.
		if rateLimitedPaths[bp] && !limiter.allow(r.RemoteAddr) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		// Two-tier register IP cap: 5/min burst + 2/24h sustained.
		// Both increment regardless of which trips first so the daily
		// counter doesn't get under-counted by an early burst denial.
		if regLimitedPaths[bp] {
			burstOK := regLimiter.allow(r.RemoteAddr)
			dailyOK := regDailyLimiter.allow(r.RemoteAddr)
			if !burstOK || !dailyOK {
				// Retry-After hint: short window if burst tripped,
				// otherwise advise the user to wait until tomorrow.
				if !burstOK {
					w.Header().Set("Retry-After", "60")
				} else {
					w.Header().Set("Retry-After", "86400")
				}
				http.Error(w, `{"error":"too many registration attempts, try again later"}`, http.StatusTooManyRequests)
				return
			}
		}
		// Block unauthenticated requests to non-public endpoints at the gateway.
		// Public prefix paths (e.g., /drive/shared/{id}) are allowed.
		isPublicPrefix := strings.HasPrefix(bp, "/drive/shared/") || strings.HasPrefix(bp, "/drive/shared-folder/")
		if !publicPaths[bp] && !isPublicPrefix && !hasCredentials(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		apiProxy.ServeHTTP(w, r)
	}
	mux.HandleFunc("/api/", apiHandler)        // legacy
	mux.HandleFunc("/app/api/", apiHandler)    // primary (new)
	mux.HandleFunc("/fakeid/api/", apiHandler) // fake id (new)

	// /r/<code> short-link redirector. Public (no auth), proxied to the
	// backend without path rewriting — gatewayBackendPath leaves /r/*
	// untouched. Backend looks up the code in short_codes and 302s to
	// <target_path>?_a=<affiliate_code>.
	mux.HandleFunc("/r/", func(w http.ResponseWriter, r *http.Request) {
		apiProxy.ServeHTTP(w, r)
	})

	// Image proxy for authenticated users.
	// Three mount points so the URL path matches the session-cookie scope
	// the browser will use:
	//   /app/proxy     bmail_session_N cookies are set with Path=/app/
	//   /fakeid/proxy  bmail_fakeid_session cookie is set with Path=/fakeid/
	//   /proxy         legacy alias for older clients / bookmarks
	// The frontend (MessageView::sanitizeHTML) picks the matching path
	// based on whether the page is under /app/ or /fakeid/, so the
	// browser sends the right cookie. The handler itself accepts any
	// session/fakeid cookie — the routing decides which one will arrive.
	mux.HandleFunc("/app/proxy", func(w http.ResponseWriter, r *http.Request) {
		imageProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/fakeid/proxy", func(w http.ResponseWriter, r *http.Request) {
		imageProxy.ServeHTTP(w, r)
	})
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		imageProxy.ServeHTTP(w, r)
	})

	// Attestation endpoint — proves this is the real enclave.
	mux.Handle("/gateway/attestation", gateway.AttestationHandler(teeRuntime, nil))

	// /.well-known/sgx-quotes/{name} — single-origin proxy that fans
	// out to the four enclaves' attestation endpoints. The /verify page
	// in the browser fetches all four quotes from this origin, avoiding
	// per-enclave CORS issues. "gateway" is served locally; the others
	// are HTTP-proxied to whichever URL the corresponding env var
	// points at, or returned as 503 if not configured.
	sgxProxy := newSGXQuotesProxy(teeRuntime, map[string]string{
		"smtp-inbound":  os.Getenv("ATTESTATION_URL_SMTP_INBOUND"),
		"smtp-outbound": os.Getenv("ATTESTATION_URL_SMTP_OUTBOUND"),
		"payment":       os.Getenv("ATTESTATION_URL_PAYMENT"),
		"keystore":      os.Getenv("ATTESTATION_URL_KEYSTORE"),
	})
	mux.Handle("/.well-known/sgx-quotes/{name}", sgxProxy)

	// robots.txt — disallow all on non-production (test/staging) servers.
	if os.Getenv("NOINDEX") == "true" {
		mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /\n"))
		})
	}

	// Everything else → static frontend (SPA fallback).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the exact file first.
		path := filepath.Join(webRoot, filepath.Clean(r.URL.Path))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Hashed assets: cache forever.
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			staticFS.ServeHTTP(w, r)
			return
		}
		// SPA fallback: serve index.html with no-cache.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(webRoot, "index.html"))
	})

	handler := http.Handler(mux)

	// Redirect non-primary domains to the primary domain (first in GATEWAY_DOMAINS).
	// Exceptions: /.well-known/ paths are served from any hostname (MTA-STS, ACME, security.txt).
	if len(domains) > 0 {
		primaryDomain := domains[0]
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host != primaryDomain && !strings.HasPrefix(r.URL.Path, "/.well-known/") {
				target := "https://" + primaryDomain + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}

	// ── TLS via Let's Encrypt ───────────────────────────────────────────

	// Graceful shutdown.
	_, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(domains) > 0 && os.Getenv("GATEWAY_PLAINHTTP") != "true" {
		// Wrap autocert's DirCache with TEE seal/unseal so cached TLS
		// keys + ACME account keys never sit on hostfs in plaintext.
		// Sealed under MRENCLAVE: any gateway code change makes the
		// cached data unreadable, autocert mints a fresh cert from GTS
		// (no rate limit). Closes the "operator with host root reads
		// /opt/bmail/certs and walks away with TLS keys" gap.
		sealedCache := gateway.NewSealedDirCache(
			autocert.DirCache(certDir),
			teeRuntime.SealUnique,
			teeRuntime.UnsealUnique,
		)

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      sealedCache,
			Email:      "andrew@vp.net",
		}

		// Optional: switch ACME directory away from Let's Encrypt.
		// Set ACME_DIRECTORY_URL to point at a different CA's ACME
		// endpoint. ACME_EAB_KID + ACME_EAB_HMAC_KEY_B64 (URL-safe base64,
		// no padding) authenticate the new-account request when the CA
		// requires External Account Binding (Google Trust Services,
		// ZeroSSL, etc.). All three env vars unset → autocert defaults
		// to Let's Encrypt with no EAB, same as before.
		if dirURL := os.Getenv("ACME_DIRECTORY_URL"); dirURL != "" {
			m.Client = &acme.Client{DirectoryURL: dirURL}
			if kid := os.Getenv("ACME_EAB_KID"); kid != "" {
				macB64 := os.Getenv("ACME_EAB_HMAC_KEY_B64")
				macBytes, err := base64.RawURLEncoding.DecodeString(macB64)
				if err != nil {
					return fmt.Errorf("decode ACME_EAB_HMAC_KEY_B64: %w", err)
				}
				m.ExternalAccountBinding = &acme.ExternalAccountBinding{
					KID: kid,
					Key: macBytes,
				}
				slog.Info("ACME using EAB", "directory", dirURL, "kid_prefix", kid[:8]+"...")
			} else {
				slog.Info("ACME using custom directory", "directory", dirURL)
			}
		}

		// HTTP server for ACME challenges + redirect.
		//
		// We wrap autocert's HTTPHandler in a webroot fallthrough that checks
		// /var/www/acme-challenges/<token> first. This lets the
		// smtp-cert-renew binary (or any out-of-process ACME client) get a
		// cert for hosts that aren't in autocert's whitelist — specifically
		// smtp.bmail.ag, where we want a cert bound to the SGX-sealed key
		// inside the smtp-inbound enclave (DANE pin chain), not autocert's
		// generated keypair. autocert still owns the challenges for its own
		// whitelisted domains; the fallthrough only fires when the file
		// exists in the webroot.
		go func() {
			httpSrv := &http.Server{
				Addr:    ":80",
				Handler: webrootACMEFirst("/var/www/acme-challenges", m.HTTPHandler(http.HandlerFunc(httpsRedirect))),
				// Slowloris protection: cap the time a client may hold the
				// connection open while still sending headers. ACME requests
				// are tiny (verifier GETs a token file) and the redirect
				// path doesn't need a long header window either, so 10s is
				// generous.
				ReadHeaderTimeout: 10 * time.Second,
			}
			slog.Info("listening for ACME challenges", "addr", ":80")
			if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
				slog.Error("HTTP server error", "error", err)
			}
		}()

		// HTTPS server.
		tlsCfg := m.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		srv := &http.Server{
			Addr:              ":443",
			Handler:           handler,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       0, // Large drive uploads need unbounded read time.
			WriteTimeout:      0, // SSE needs no write timeout.
			IdleTimeout:       120 * time.Second,
		}
		slog.Info("gateway listening", "addr", ":443", "tls", true, "domains", domains)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			return fmt.Errorf("HTTPS listen: %v", err)
		}
	} else {
		// Dev mode: plain HTTP.
		addr := os.Getenv("GATEWAY_ADDR")
		if addr == "" {
			addr = ":8080"
		}
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		slog.Info("gateway listening (plain HTTP, dev mode)", "addr", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("listen: %v", err)
		}
	}

	return nil
}

// httpsRedirect redirects HTTP to HTTPS.
// Uses the request Host only if it matches a configured domain;
// otherwise responds 421 to prevent open redirect via spoofed Host header.
func httpsRedirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !allowedDomainSet[host] {
		http.Error(w, "invalid host", http.StatusMisdirectedRequest)
		return
	}
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// allowedDomainSet is populated from GATEWAY_DOMAINS at startup.
var allowedDomainSet = make(map[string]bool)

// ── Privacy-Preserving Rate Limiter ─────────────────────────────────────

type ipRateLimiter struct {
	mu          sync.Mutex
	sketch      *gateway.CountMinSketch
	limit       int
	window      time.Duration
	salt        [32]byte
	windowStart time.Time
	saltRotated time.Time
}

// newIPRateLimiter builds a per-IP CountMinSketch counter with a
// rolling window. window controls how often the sketch is reset; the
// salt is also rotated at least every 24h regardless of window so we
// never accumulate long-term per-IP profiles. For windows ≥ 24h the
// salt rotation lines up with the window reset; for shorter windows
// the sketch resets more often than the salt.
func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	var salt [32]byte
	rand.Read(salt[:])
	now := time.Now()
	return &ipRateLimiter{
		sketch:      gateway.NewCountMinSketch(4096, 4),
		limit:       limit,
		window:      window,
		salt:        salt,
		windowStart: now,
		saltRotated: now,
	}
}

func (rl *ipRateLimiter) allow(remoteAddr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Salt rotation cap: never older than max(24h, window). Prevents
	// long-term IP tracking even when window is short.
	saltCap := 24 * time.Hour
	if rl.window > saltCap {
		saltCap = rl.window
	}
	if now.Sub(rl.saltRotated) >= saltCap {
		rand.Read(rl.salt[:])
		rl.saltRotated = now
		rl.sketch.Reset()
	}

	// Reset sketch when the window elapses.
	if now.Sub(rl.windowStart) >= rl.window {
		rl.sketch.Reset()
		rl.windowStart = now
	}

	key := hashIP(remoteAddr, rl.salt[:])
	rl.sketch.Increment(key)
	return rl.sketch.Estimate(key) <= rl.limit
}

func hashIP(remoteAddr string, salt []byte) []byte {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	h := sha256.New()
	h.Write([]byte(host))
	h.Write(salt)
	return h.Sum(nil)
}

// ── Image/Resource Proxy ────────────────────────────────────────────────

func newImageProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Require a session cookie (user must be authenticated).
		// The frontend uses indexed cookies (bmail_session_0, _1, …) for
		// multi-account support and bmail_fakeid_session for fake-ID
		// browsing — accept any of them, plus the legacy bmail_session.
		// We don't need to validate the session value here; the proxy just
		// gates "is this a logged-in browser at all", and the cookie
		// existence is sufficient (the cookie is HttpOnly + Secure +
		// SameSite, so it can't be forged from another origin).
		authed := false
		for _, c := range r.Cookies() {
			if c.Name == "bmail_session" || c.Name == "bmail_fakeid_session" || strings.HasPrefix(c.Name, "bmail_session_") {
				if c.Value != "" {
					authed = true
					break
				}
			}
		}
		if !authed {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}

		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, `{"error":"url parameter required"}`, http.StatusBadRequest)
			return
		}

		parsed, err := url.Parse(targetURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			http.Error(w, `{"error":"invalid url"}`, http.StatusBadRequest)
			return
		}

		// SSRF prevention: resolve DNS and block private/loopback IPs.
		// Resolve before making the request to prevent DNS rebinding (TOCTOU).
		host := parsed.Hostname()
		ips, err := net.DefaultResolver.LookupIPAddr(r.Context(), host)
		if err != nil || len(ips) == 0 {
			// If host is a literal IP, validate it directly.
			if ip := net.ParseIP(host); ip != nil {
				ips = []net.IPAddr{{IP: ip}}
			} else {
				http.Error(w, `{"error":"dns resolution failed"}`, http.StatusBadGateway)
				return
			}
		}
		for _, addr := range ips {
			if addr.IP.IsLoopback() || addr.IP.IsPrivate() || addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() || addr.IP.IsUnspecified() {
				http.Error(w, `{"error":"blocked address"}`, http.StatusForbidden)
				return
			}
		}

		// Use a custom dialer that forces connection to the resolved IP to prevent
		// DNS rebinding between our check and the actual connection.
		resolvedAddr := ips[0].IP.String()
		proxyTransport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(resolvedAddr, port))
			},
			TLSHandshakeTimeout: 10 * time.Second,
		}
		proxyClient := &http.Client{Transport: proxyTransport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}}

		// Fetch the resource. The external server sees the enclave's IP, not the user's.
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
		if err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		// Don't forward any identifying headers.
		req.Header.Set("User-Agent", "bmail-proxy/1.0")
		req.Header.Set("Accept", r.Header.Get("Accept"))

		resp, err := proxyClient.Do(req)
		if err != nil {
			http.Error(w, `{"error":"fetch failed"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Forward content type and cache headers.
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(resp.StatusCode)

		// Limit response size (10MB max).
		io.Copy(w, io.LimitReader(resp.Body, 10<<20))
	})
}

// gatewayBackendPath normalizes client-facing API URLs to the backend-facing
// form. The backend's handler tree is registered at the backend-facing paths
// (e.g. /auth/login, /fakeid/auth/login); rate-limit and public-path maps in
// the gateway use the same keys. Keeping the /fakeid/ prefix through the
// rewrite is what lets backend middleware (IsFakeIDPath) distinguish Fake ID
// requests from primary ones.
//
//	/app/api/x    → /x
//	/fakeid/api/x → /fakeid/x
//	/api/x        → /x   (legacy)
//	anything else → unchanged (static file paths, /proxy, /.well-known, etc.)
func gatewayBackendPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/app/api/"):
		return strings.TrimPrefix(p, "/app/api")
	case p == "/app/api":
		return "/"
	case strings.HasPrefix(p, "/fakeid/api/"):
		return "/fakeid" + strings.TrimPrefix(p, "/fakeid/api")
	case p == "/fakeid/api":
		return "/fakeid"
	case strings.HasPrefix(p, "/api/"):
		return strings.TrimPrefix(p, "/api")
	case p == "/api":
		return "/"
	}
	return p
}

// webrootACMEFirst returns an http.Handler that, for paths under
// /.well-known/acme-challenge/, first looks for the token as a file in
// webroot. If found, it serves the file's contents (the ACME key
// authorization string). Otherwise it falls through to next, which is
// autocert's HTTPHandler — preserving autocert's challenge handling for
// its own whitelisted hosts.
//
// This is what lets the smtp-cert-renew binary issue a Let's Encrypt
// cert for smtp.bmail.ag (bound to the SGX-sealed key) without conflicting
// with gateway's autocert. The renewer drops a token file in webroot;
// autocert never sees it; the gateway hands LE the response.
//
// Tokens are constrained to base64url alphabet (A-Z a-z 0-9 - _) to defang
// path traversal.
func webrootACMEFirst(webroot string, next http.Handler) http.Handler {
	const prefix = "/.well-known/acme-challenge/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if !validACMEToken(token) {
			next.ServeHTTP(w, r)
			return
		}
		path := filepath.Join(webroot, token)
		data, err := os.ReadFile(path)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	})
}

func validACMEToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}
